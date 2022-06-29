import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/commands.dart';
import 'package:yubikit_openpgp/key_data.dart';
import 'package:yubikit_openpgp/smartcard/application.dart';

import 'curve.dart';
import 'keyslot.dart';
import 'smartcard/exception.dart';
import 'smartcard/interface.dart';
import 'smartcard/pin_provider.dart';
import 'smartcard/response.dart';
import 'touch_mode.dart';

export 'curve.dart';
export 'key_data.dart';
export 'keyslot.dart';
export 'smartcard/application.dart';
export 'smartcard/exception.dart';
export 'smartcard/instruction.dart';
export 'smartcard/interface.dart';
export 'smartcard/pin_provider.dart';
export 'smartcard/response.dart';
export 'touch_mode.dart';
export 'commands.dart';

class YubikitOpenPGP {
  static const String defaultPin = '123456';
  static const String defaultAdminPin = '12345678';

  static const application = Application.openpgp;
  final YubikitOpenPGPCommands _commands;
  final SmartCardInterface _smartCardInterface;
  final PinProvider _pinProvider;

  const YubikitOpenPGP(this._smartCardInterface, this._pinProvider,
      [this._commands = const YubikitOpenPGPCommands()]);

  Future<ECKeyData> generateECKey(KeySlot keySlot, ECCurve curve,
      [int? timestamp]) async {
    final responses = await (await _smartCardInterface.sendCommands(
            application,
            [
              _commands.setECKeyAttributes(keySlot, curve),
              _commands.generateAsymmetricKey(keySlot)
            ],
            verify: _commands.verifyAdminPin(_pinProvider.adminPin)))
        .toList();
    final generateResponse = responses[1];
    if (generateResponse is SuccessfulResponse) {
      timestamp ??= DateTime.now().millisecondsSinceEpoch;
      await _smartCardInterface.sendCommands(
          application,
          [
            _commands.setECKeyFingerprint(
                keySlot, curve, generateResponse.response),
            _commands.setGenerationTime(keySlot, timestamp)
          ],
          verify: _commands.verifyAdminPin(_pinProvider.adminPin));
      return ECKeyData.fromBytes(generateResponse.response, keySlot);
    } else if (generateResponse is ErrorResponse) {
      throw generateResponse.exception;
    }
    throw Exception('Invalid response type ${generateResponse.runtimeType}');
  }

  Future<RSAKeyData> generateRSAKey(KeySlot keySlot, int keySize,
      [int? timestamp]) async {
    final responses = await (await _smartCardInterface.sendCommands(
            application,
            [
              _commands.setRsaKeyAttributes(keySlot, keySize),
              _commands.generateAsymmetricKey(keySlot)
            ],
            verify: _commands.verifyAdminPin(_pinProvider.adminPin)))
        .toList();
    final generateResponse = responses[1];
    if (generateResponse is SuccessfulResponse) {
      timestamp ??= DateTime.now().millisecondsSinceEpoch;
      await _smartCardInterface.sendCommands(
          application,
          [
            _commands.setRsaKeyFingerprint(keySlot, generateResponse.response),
            _commands.setGenerationTime(keySlot, timestamp)
          ],
          verify: _commands.verifyAdminPin(_pinProvider.adminPin));
      return RSAKeyData.fromBytes(generateResponse.response, keySlot);
    } else if (generateResponse is ErrorResponse) {
      throw generateResponse.exception;
    }
    throw Exception('Invalid response type ${generateResponse.runtimeType}');
  }

  Future<KeyData?> getPublicKey(KeySlot keySlot) async {
    try {
      final response = await _smartCardInterface.sendCommand(
          application, _commands.getAsymmetricPublicKey(keySlot));
      return KeyData.fromBytes(response, keySlot);
    } on SmartCardException catch (e) {
      if (e.error == SmartCardError.memoryFailure) {
        return null;
      }
      rethrow;
    }
  }

  Future<Map<KeySlot, KeyData?>> getAllPublicKeys() async {
    final commands = [
      _commands.getAsymmetricPublicKey(KeySlot.signature),
      _commands.getAsymmetricPublicKey(KeySlot.encryption),
      _commands.getAsymmetricPublicKey(KeySlot.authentication),
    ];
    final results =
        await _smartCardInterface.sendCommands(application, commands);
    final result = await results.toList();
    final entries = <MapEntry<KeySlot, KeyData?>>[];
    entries.add(_keyEntry(KeySlot.signature, result[0]));
    entries.add(_keyEntry(KeySlot.encryption, result[1]));
    entries.add(_keyEntry(KeySlot.authentication, result[2]));
    return Map.fromEntries(entries);
  }

  MapEntry<KeySlot, KeyData?> _keyEntry(
      KeySlot keySlot, SmartCardResponse response) {
    if (response is SuccessfulResponse) {
      return MapEntry(keySlot, KeyData.fromBytes(response.response, keySlot));
    }
    return MapEntry(keySlot, null);
  }

  Future<Uint8List> ecSign(List<int> data) async {
    return _smartCardInterface.sendCommand(application, _commands.ecSign(data),
        verify: _commands.verifySignaturePin(_pinProvider.pin));
  }

  Future<Uint8List> rsaSign(List<int> data) async {
    return _smartCardInterface.sendCommand(application, _commands.rsaSign(data),
        verify: _commands.verifySignaturePin(_pinProvider.pin));
  }

  Future<Uint8List> ecSharedSecret(List<int> publicKey) async {
    return _smartCardInterface.sendCommand(
        application, _commands.ecSharedSecret(publicKey),
        verify: _commands.verifyEncryptionPin(_pinProvider.pin));
  }

  Future<Uint8List> decipher(List<int> ciphertext) async {
    final response = await _smartCardInterface.sendCommand(
        application, _commands.decipher(ciphertext),
        verify: _commands.verifyEncryptionPin(_pinProvider.pin));
    return response;
  }

  Future<TouchMode> getTouchMode(KeySlot keySlot) async {
    final data = await _smartCardInterface.sendCommand(
        application, _commands.getTouch(keySlot));
    return TouchModeValues.parse(data);
  }

  Future<void> setTouchMode(KeySlot keySlot, TouchMode mode) async {
    await _smartCardInterface.sendCommand(
        application, _commands.setTouch(keySlot, mode));
  }

  Future<OpenPGPVersion> getOpenPGPVersion() async {
    final response = await _smartCardInterface.sendCommand(
        application, _commands.getOpenPGPVersion());
    return OpenPGPVersion.fromBytes(response);
  }

  Future<ApplicationVersion> getApplicationVersion() async {
    final response = await _smartCardInterface.sendCommand(
        application, _commands.getApplicationVersion());
    return ApplicationVersion.fromBytes(response);
  }

  Future<PinRetries> getRemainingPinTries() async {
    final response = await _smartCardInterface.sendCommand(
        application, _commands.getRemainingPinTries());
    return PinRetries.fromBytes(response);
  }

  Future<void> setRemainingPinTries(
      int pw1Tries, int pw2Tries, int pw3Tries) async {
    await _smartCardInterface.sendCommand(
        application, _commands.setPinRetries(pw1Tries, pw2Tries, pw3Tries));
  }

  Future<void> reset() async {
    final commands = [
      ..._blockPins(),
      _commands.terminate(),
      _commands.activate()
    ];
    await _smartCardInterface.sendCommands(Application.openpgp, commands);
  }

  List<Uint8List> _blockPins() {
    const commands = YubikitOpenPGPCommands();
    const invalidPin = '00000000';
    final pinCommands = Iterable.generate(9)
        .map((e) => commands.verifySignaturePin(invalidPin))
        .toList();
    final adminPinCommands = Iterable.generate(9)
        .map((e) => commands.verifyAdminPin(invalidPin))
        .toList();
    return pinCommands + adminPinCommands;
  }
}

class OpenPGPVersion {
  final int major, minor;

  const OpenPGPVersion(this.major, this.minor);

  factory OpenPGPVersion.fromBytes(List<int> response) {
    return OpenPGPVersion(response[6], response[7]);
  }
}

class ApplicationVersion {
  final int major, minor, patch;

  const ApplicationVersion(this.major, this.minor, this.patch);

  factory ApplicationVersion.fromBytes(List<int> response) {
    final hexData = hex.encode(response);
    return ApplicationVersion(int.parse(hexData.substring(0, 2)),
        int.parse(hexData.substring(2, 4)), int.parse(hexData.substring(4, 6)));
  }
}

class PinRetries {
  final int pin, reset, admin;

  const PinRetries(this.pin, this.reset, this.admin);

  factory PinRetries.fromBytes(List<int> response) {
    return PinRetries(response[4], response[5], response[6]);
  }
}
