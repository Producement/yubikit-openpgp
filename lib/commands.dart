import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/dart.dart';
import 'package:yubikit_openpgp/tlv.dart';
import 'package:yubikit_openpgp/utils.dart';

import 'curve.dart';
import 'data_object.dart';
import 'hash_algorithm.dart';
import 'keyslot.dart';
import 'smartcard/instruction.dart';
import 'touch_mode.dart';

class YubikitOpenPGPCommands {
  static const int _touchMethodButton = 0x20;
  static const int pw1_81 = 0x81;
  static const int pw1_82 = 0x82;
  static const int pw3_83 = 0x83;
  static const sha512 = DartSha512();

  const YubikitOpenPGPCommands();

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

  Uint8List generateAsymmetricKey(KeySlot keySlot) {
    return _toApdu(0x00, Instruction.generateAsym, 0x80, 0x00, keySlot.crt);
  }

  Uint8List getAsymmetricPublicKey(KeySlot keySlot) {
    return _toApdu(0x00, Instruction.generateAsym, 0x81, 0x00, keySlot.crt);
  }

  Uint8List setGenerationTime(KeySlot keySlot, int timestamp) {
    final timestampBytes = ByteData(4)..setInt32(0, timestamp);
    return _setData(keySlot.genTime, timestampBytes.buffer.asUint8List());
  }

  Uint8List setECKeyFingerprint(
      KeySlot keySlot, ECCurve curve, List<int> response) {
    final data = TlvData.parse(response).get(0x7F49);
    final publicKey = data.getValue(0x86);
    return _setData(
        keySlot.fingerprint,
        PGPUtils.calculateECFingerprint(
            BigInt.parse(hex.encode(publicKey), radix: 16), curve));
  }

  Uint8List setRsaKeyFingerprint(KeySlot keySlot, List<int> response) {
    final data = TlvData.parse(response).get(0x7F49);
    final modulus = data.getValue(0x81);
    final exponent = data.getValue(0x82);
    return _setData(keySlot.fingerprint,
        PGPUtils.calculateRSAFingerprint(modulus, exponent));
  }

  Uint8List setECKeyAttributes(KeySlot keySlot, ECCurve curve) {
    final attributes = _formatECAttributes(keySlot, curve);
    return _setData(keySlot.keyId, attributes);
  }

  List<int> _formatRSAAttributes(KeySlot keySlot, int keySize) {
    return [0x01, keySize >> 8, keySize & 0xFF, 0x00, 0x20, 0x00];
  }

  Uint8List setRsaKeyAttributes(KeySlot keySlot, int keySize) {
    final attributes = _formatRSAAttributes(keySlot, keySize);
    return _setData(keySlot.keyId, attributes);
  }

  Uint8List ecSign(List<int> data) {
    final digest = sha512.hashSync(data);
    return _toApdu(
        0x00, Instruction.performSecurityOperation, 0x9E, 0x9A, digest.bytes);
  }

  Uint8List rsaSign(List<int> data) {
    final digest = sha512.hashSync(data);
    const hashAlgorithm = HashAlgorithm.sha512;
    final digestInfo = [
      0x30,
      0x51,
      0x30,
      0x0D,
      0x06,
      hashAlgorithm.oid.length,
      ...(hashAlgorithm.oid),
      0x05,
      0x00,
      0x04,
      0x40,
      ...digest.bytes
    ];
    return _toApdu(
        0x00, Instruction.performSecurityOperation, 0x9E, 0x9A, digestInfo);
  }

  Uint8List ecSharedSecret(List<int> publicKey) {
    final externalPublicKey = [0x86, publicKey.length, ...publicKey];
    final publicKeyDo = [
      0x7F,
      0x49,
      externalPublicKey.length,
      ...externalPublicKey
    ];
    final cipherDo = [0xA6, publicKeyDo.length, ...publicKeyDo];
    return _toApdu(
        0x00, Instruction.performSecurityOperation, 0x80, 0x86, cipherDo);
  }

  Uint8List decipher(List<int> ciphertext) {
    final data = [0x00, ...ciphertext];
    return _toApdu(
        0x00, Instruction.performSecurityOperation, 0x80, 0x86, data);
  }

  Uint8List getTouch(KeySlot keySlot) {
    return _getData(keySlot.uif);
  }

  Uint8List setTouch(KeySlot keySlot, TouchMode mode) {
    return _setData(keySlot.uif, [mode.value, _touchMethodButton]);
  }

  Uint8List getOpenPGPVersion() {
    return _getData(DataObject.aid.value);
  }

  Uint8List getApplicationVersion() {
    return _toApdu(0x00, Instruction.getVersion, 0x00, 0x00, []);
  }

  Uint8List getRemainingPinTries() {
    return _getData(DataObject.pwStatus.value);
  }

  Uint8List setPinRetries(int pw1Tries, int pw2Tries, int pw3Tries) {
    return _toApdu(0x00, Instruction.setPinRetries, 0x00, 0x00,
        [pw1Tries, pw2Tries, pw3Tries]);
  }

  Uint8List terminate() {
    return _toApdu(0x00, Instruction.terminate, 0, 0, []);
  }

  Uint8List activate() {
    return _toApdu(0x00, Instruction.activate, 0, 0, []);
  }

  Uint8List _getData(int cmd) {
    final response =
        _toApdu(0x00, Instruction.getData, cmd >> 8, cmd & 0xFF, []);
    return response;
  }

  Uint8List _setData(int cmd, List<int> data) {
    final response =
        _toApdu(0x00, Instruction.putData, cmd >> 8, cmd & 0xFF, data);
    return response;
  }

  Uint8List _toApdu(
      int cla, Instruction instruction, int p1, int p2, List<int> data) {
    return instruction.apdu(cla, p1, p2, data);
  }

  Uint8List verifySignaturePin(String pin) {
    return Uint8List.fromList(_verify(pw1_81, pin));
  }

  Uint8List verifyEncryptionPin(String pin) {
    return Uint8List.fromList(_verify(pw1_82, pin));
  }

  Uint8List verifyAdminPin(String adminPin) {
    return Uint8List.fromList(_verify(pw3_83, adminPin));
  }

  List<int> _verify(int pw, String pin) {
    final pinData = pin.codeUnits;
    return [0x00, Instruction.verify.value, 0, pw, pinData.length, ...pinData];
  }
}
