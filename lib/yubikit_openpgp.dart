import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:tuple/tuple.dart';

import 'curve.dart';
import 'data_object.dart';
import 'keyslot.dart';
import 'smartcard/instruction.dart';
import 'smartcard/pin_provider.dart';
import 'smartcard/interface.dart';
import 'tlv.dart';
import 'touch_mode.dart';
import 'utils.dart';

export 'curve.dart';
export 'keyslot.dart';
export 'smartcard/application.dart';
export 'smartcard/interface.dart';
export 'smartcard/instruction.dart';
export 'smartcard/pin_provider.dart';
export 'smartcard/exception.dart';
export 'touch_mode.dart';

class YubikitOpenPGP {
  static const String defaultPin = '123456';
  static const String defaultAdminPin = '12345678';

  static const int pw1_81 = 0x81;
  static const int pw1_82 = 0x82;
  static const int pw3_83 = 0x83;

  final SmartCardInterface _smartCardInterface;
  final PinProvider _pinProvider;

  const YubikitOpenPGP(this._smartCardInterface, this._pinProvider);

  List<int> _formatECAttributes(KeySlot keySlot, ECCurve curve) {
    late int algorithm;
    if ([ECCurve.ed25519, ECCurve.x25519].contains(curve)) {
      algorithm = 0x16;
    } else if (keySlot == KeySlot.encryption) {
      algorithm = 0x12;
    } else {
      algorithm = 0x13;
    }
    return [algorithm].followedBy(curve.oid).toList();
  }

  Future<Uint8List> generateECKey(KeySlot keySlot, ECCurve curve,
      [int? timestamp]) async {
    final attributes = _formatECAttributes(keySlot, curve);
    await _setData(keySlot.keyId, attributes,
        verify: _verifyCommand(pw3_83, _pinProvider.adminPin));
    final response = await _smartCardInterface.sendApdu(
        0x00, Instruction.generateAsym, 0x80, 0x00, keySlot.crt,
        verify: _verifyCommand(pw3_83, _pinProvider.adminPin));
    final data = TlvData.parse(response).get(0x7F49);
    final publicKey = data.getValue(0x86);
    await _setData(
        keySlot.fingerprint,
        PGPUtils.calculateFingerprint(
            BigInt.parse(hex.encode(publicKey), radix: 16), curve),
        verify: _verifyCommand(pw3_83, _pinProvider.adminPin));
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    final timestampBytes = ByteData(4)..setInt32(0, timestamp);
    await _setData(keySlot.genTime, timestampBytes.buffer.asUint8List(),
        verify: _verifyCommand(pw3_83, _pinProvider.adminPin));
    return publicKey;
  }

  Future<Uint8List?> getECPublicKey(KeySlot keySlot) async {
    try {
      final response = await _smartCardInterface.sendApdu(
          0x00, Instruction.generateAsym, 0x81, 0x00, keySlot.crt);
      final data = TlvData.parse(response).get(0x7F49);
      return data.getValue(0x86);
    } catch (e) {
      return null;
    }
  }

  Future<Uint8List> sign(List<int> data) async {
    final digest = sha512.convert(data);
    final response = await _smartCardInterface.sendApdu(
        0x00, Instruction.performSecurityOperation, 0x9E, 0x9A, digest.bytes,
        verify: _verifyCommand(pw1_81, _pinProvider.pin));
    return response;
  }

  Future<Uint8List> ecSharedSecret(List<int> publicKey) async {
    final externalPublicKey = [0x86, publicKey.length] + publicKey;
    final publicKeyDo =
        [0x7F, 0x49, externalPublicKey.length] + externalPublicKey;
    final cipherDo = [0xA6, publicKeyDo.length] + publicKeyDo;
    final response = await _smartCardInterface.sendApdu(
        0x00, Instruction.performSecurityOperation, 0x80, 0x86, cipherDo,
        verify: _verifyCommand(pw1_82, _pinProvider.pin));
    return response;
  }

  Future<TouchMode> getTouch(KeySlot keySlot) async {
    final data = await _getData(keySlot.uif);
    return TouchModeValues.parse(data);
  }

  static const int _touchMethodButton = 0x20;

  Future<void> setTouch(KeySlot keySlot, TouchMode mode) async {
    await _setData(keySlot.uif, [mode.value, _touchMethodButton]);
  }

  Future<Tuple2<int, int>> getOpenPGPVersion() async {
    final data = await _getData(DataObject.aid.value);
    return Tuple2(data[6], data[7]);
  }

  Future<Tuple3<int, int, int>> getApplicationVersion() async {
    final data = await _smartCardInterface
        .sendApdu(0x00, Instruction.getVersion, 0x00, 0x00, []);
    var hexData = hex.encode(data);
    return Tuple3(int.parse(hexData.substring(0, 2)),
        int.parse(hexData.substring(2, 4)), int.parse(hexData.substring(4, 6)));
  }

  Future<PinRetries> getRemainingPinTries() async {
    final data = await _getData(DataObject.pwStatus.value);
    return PinRetries(data[4], data[5], data[6]);
  }

  Future<void> setPinRetries(int pw1Tries, int pw2Tries, int pw3Tries) async {
    await _smartCardInterface.sendApdu(0x00, Instruction.setPinRetries, 0x00,
        0x00, [pw1Tries, pw2Tries, pw3Tries]);
  }

  List<int> _verifyCommand(int pw, String pin) {
    final pinData = pin.codeUnits;
    return [0x00, Instruction.verify.value, 0, pw, pinData.length] + pinData;
  }

  Future<void> reset() async {
    await _blockPins();
    await _smartCardInterface.sendApdu(0x00, Instruction.terminate, 0, 0, []);
    await _smartCardInterface.sendApdu(0x00, Instruction.activate, 0, 0, []);
  }

  Future<void> _blockPins() async {
    var invalidPin = [0, 0, 0, 0, 0, 0, 0, 0];
    PinRetries retries = await getRemainingPinTries();
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.pin)) {
      try {
        await _smartCardInterface.sendApdu(
            0x00, Instruction.verify, 0x00, pw1_81, invalidPin);
      } catch (e) {
        //Ignore
      }
    }
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.admin)) {
      try {
        await _smartCardInterface.sendApdu(
            0x00, Instruction.verify, 0x00, pw3_83, invalidPin);
      } catch (e) {
        //Ignore
      }
    }
  }

  Future<List<int>> _getData(int cmd) async {
    final response = await _smartCardInterface
        .sendApdu(0x00, Instruction.getData, cmd >> 8, cmd & 0xFF, []);
    return response;
  }

  Future<List<int>> _setData(int cmd, List<int> data,
      {List<int>? verify}) async {
    final response = await _smartCardInterface.sendApdu(
        0x00, Instruction.putData, cmd >> 8, cmd & 0xFF, data,
        verify: verify);
    return response;
  }
}

class PinRetries {
  final int pin, reset, admin;

  const PinRetries(this.pin, this.reset, this.admin);
}

extension Tuple3Compare on Tuple3 {
  bool operator <(Tuple3 other) {
    if (item1 < other.item1) {
      return true;
    } else if (item1 == other.item1) {
      if (item2 < other.item2) {
        return true;
      } else if (item2 == other.item2) {
        return item3 < other.item3;
      }
    }
    return false;
  }

  bool operator >(Tuple3 other) {
    if (item1 > other.item1) {
      return true;
    } else if (item1 == other.item1) {
      if (item2 > other.item2) {
        return true;
      } else if (item2 == other.item2) {
        return item3 > other.item3;
      }
    }
    return false;
  }
}
