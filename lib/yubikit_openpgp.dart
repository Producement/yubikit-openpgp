import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:tuple/tuple.dart';
import 'package:yubikit_openpgp/commands.dart';
import 'package:yubikit_openpgp/key_data.dart';
import 'package:yubikit_openpgp/smartcard/application.dart';

import 'curve.dart';
import 'keyslot.dart';
import 'smartcard/exception.dart';
import 'smartcard/interface.dart';
import 'smartcard/pin_provider.dart';
import 'tlv.dart';
import 'touch_mode.dart';

export 'curve.dart';
export 'key_data.dart';
export 'keyslot.dart';
export 'smartcard/application.dart';
export 'smartcard/exception.dart';
export 'smartcard/instruction.dart';
export 'smartcard/interface.dart';
export 'smartcard/pin_provider.dart';
export 'touch_mode.dart';
export 'commands.dart';

class YubikitOpenPGP {
  static const String defaultPin = '123456';
  static const String defaultAdminPin = '12345678';

  static const int pw1_81 = 0x81;
  static const int pw1_82 = 0x82;
  static const int pw3_83 = 0x83;

  static final application = Application.openpgp;
  final YubikitOpenPGPCommands commands;
  final SmartCardInterface _smartCardInterface;
  final PinProvider _pinProvider;

  const YubikitOpenPGP(this._smartCardInterface, this._pinProvider,
      {this.commands = const YubikitOpenPGPCommands()});

  Future<ECKeyData> generateECKey(KeySlot keySlot, ECCurve curve,
      [int? timestamp]) async {
    await _smartCardInterface.sendCommand(application,
        commands.setECKeyAttributes(keySlot, curve, _pinProvider.adminPin));
    final response = await _smartCardInterface.sendCommand(application,
        commands.generateAsymmetricKey(keySlot, _pinProvider.adminPin));
    final data = TlvData.parse(response).get(0x7F49);
    final publicKey = data.getValue(0x86);
    await _smartCardInterface.sendCommand(
        application,
        commands.setECKeyFingerprint(
            keySlot, curve, publicKey, _pinProvider.adminPin));
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    await _smartCardInterface.sendCommand(application,
        commands.setGenerationTime(keySlot, timestamp, _pinProvider.adminPin));
    return ECKeyData(publicKey, curve.type);
  }

  Future<RSAKeyData> generateRSAKey(KeySlot keySlot, int keySize,
      [int? timestamp]) async {
    await _smartCardInterface.sendCommand(application,
        commands.setRsaKeyAttributes(keySlot, keySize, _pinProvider.adminPin));
    final response = await _smartCardInterface.sendCommand(application,
        commands.generateAsymmetricKey(keySlot, _pinProvider.adminPin));
    final data = TlvData.parse(response).get(0x7F49);
    final modulus = data.getValue(0x81);
    final exponent = data.getValue(0x82);
    await _smartCardInterface.sendCommand(
        application,
        commands.setRsaKeyFingerprint(
            keySlot, modulus, exponent, _pinProvider.adminPin));
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    await _smartCardInterface.sendCommand(application,
        commands.setGenerationTime(keySlot, timestamp, _pinProvider.adminPin));
    return RSAKeyData(modulus, exponent);
  }

  Future<KeyData?> getPublicKey(KeySlot keySlot) async {
    try {
      final response = await _smartCardInterface.sendCommand(
          application, commands.getAsymmetricPublicKey(keySlot));
      final data = TlvData.parse(response).get(0x7F49);
      if (data.hasValue(0x86)) {
        return ECKeyData(
            data.getValue(0x86),
            keySlot == KeySlot.signature
                ? cryptography.KeyPairType.ed25519
                : cryptography.KeyPairType.x25519);
      } else {
        return RSAKeyData(data.getValue(0x81), data.getValue(0x82));
      }
    } on SmartCardException catch (e) {
      if (e.getError() == SmartCardError.memoryFailure) {
        return null;
      }
      rethrow;
    }
  }

  Future<Uint8List> ecSign(List<int> data) async {
    return _smartCardInterface.sendCommand(
        application, commands.ecSign(data, _pinProvider.pin));
  }

  Future<Uint8List> rsaSign(List<int> data) async {
    return _smartCardInterface.sendCommand(
        application, commands.rsaSign(data, _pinProvider.pin));
  }

  Future<Uint8List> ecSharedSecret(List<int> publicKey) async {
    return _smartCardInterface.sendCommand(
        application, commands.ecSharedSecret(publicKey, _pinProvider.pin));
  }

  Future<Uint8List> decipher(List<int> ciphertext) async {
    final response = await _smartCardInterface.sendCommand(
        application, commands.decipher(ciphertext, _pinProvider.pin));
    return response;
  }

  Future<TouchMode> getTouch(KeySlot keySlot) async {
    final data = await _smartCardInterface.sendCommand(
        application, commands.getTouch(keySlot));
    return TouchModeValues.parse(data);
  }

  Future<void> setTouch(KeySlot keySlot, TouchMode mode) async {
    await _smartCardInterface.sendCommand(
        application, commands.setTouch(keySlot, mode));
  }

  Future<Tuple2<int, int>> getOpenPGPVersion() async {
    final data = await _smartCardInterface.sendCommand(
        application, commands.getOpenPGPVersion());
    return Tuple2(data[6], data[7]);
  }

  Future<Tuple3<int, int, int>> getApplicationVersion() async {
    final data = await _smartCardInterface.sendCommand(
        application, commands.getApplicationVersion());
    var hexData = hex.encode(data);
    return Tuple3(int.parse(hexData.substring(0, 2)),
        int.parse(hexData.substring(2, 4)), int.parse(hexData.substring(4, 6)));
  }

  Future<PinRetries> getRemainingPinTries() async {
    final data = await _smartCardInterface.sendCommand(
        application, commands.getRemainingPinTries());
    return PinRetries(data[4], data[5], data[6]);
  }

  Future<void> setPinRetries(int pw1Tries, int pw2Tries, int pw3Tries) async {
    await _smartCardInterface.sendCommand(
        application, commands.setPinRetries(pw1Tries, pw2Tries, pw3Tries));
  }

  Future<void> reset() async {
    await _blockPins();
    await _smartCardInterface.sendCommand(application, commands.terminate());
    await _smartCardInterface.sendCommand(application, commands.activate());
  }

  Future<void> _blockPins() async {
    var invalidPin = '00000000';
    PinRetries retries = await getRemainingPinTries();
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.pin)) {
      try {
        await _smartCardInterface.sendCommand(
            application, commands.verify(pw1_81, invalidPin));
      } catch (e) {
        //Ignore
      }
    }
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.admin)) {
      try {
        await _smartCardInterface.sendCommand(
            application, commands.verify(pw3_83, invalidPin));
      } catch (e) {
        //Ignore
      }
    }
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
