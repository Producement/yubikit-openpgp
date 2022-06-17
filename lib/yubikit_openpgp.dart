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

  static final application = Application.openpgp;
  final YubikitOpenPGPCommands _commands;
  final SmartCardInterface _smartCardInterface;
  final PinProvider _pinProvider;

  const YubikitOpenPGP(this._smartCardInterface, this._pinProvider,
      [this._commands = const YubikitOpenPGPCommands()]);

  Future<ECKeyData> generateECKey(KeySlot keySlot, ECCurve curve,
      [int? timestamp]) async {
    await _smartCardInterface.sendCommand(
        application, _commands.setECKeyAttributes(keySlot, curve),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    final response = await _smartCardInterface.sendCommand(
        application, _commands.generateAsymmetricKey(keySlot),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    await _smartCardInterface.sendCommand(
        application, _commands.setECKeyFingerprint(keySlot, curve, response),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    await _smartCardInterface.sendCommand(
        application, _commands.setGenerationTime(keySlot, timestamp),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    return ECKeyData.fromBytes(response, keySlot);
  }

  Future<RSAKeyData> generateRSAKey(KeySlot keySlot, int keySize,
      [int? timestamp]) async {
    await _smartCardInterface.sendCommand(
        application, _commands.setRsaKeyAttributes(keySlot, keySize),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    final response = await _smartCardInterface.sendCommand(
        application, _commands.generateAsymmetricKey(keySlot),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    await _smartCardInterface.sendCommand(
        application, _commands.setRsaKeyFingerprint(keySlot, response),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    await _smartCardInterface.sendCommand(
        application, _commands.setGenerationTime(keySlot, timestamp),
        verify: _commands.verifyAdminPin(_pinProvider.adminPin));
    return RSAKeyData.fromBytes(response, keySlot);
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

  Future<TouchMode> getTouch(KeySlot keySlot) async {
    final data = await _smartCardInterface.sendCommand(
        application, _commands.getTouch(keySlot));
    return TouchModeValues.parse(data);
  }

  Future<void> setTouch(KeySlot keySlot, TouchMode mode) async {
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

  Future<void> setPinRetries(int pw1Tries, int pw2Tries, int pw3Tries) async {
    await _smartCardInterface.sendCommand(
        application, _commands.setPinRetries(pw1Tries, pw2Tries, pw3Tries));
  }

  Future<void> reset() async {
    await _blockPins();
    await _smartCardInterface.sendCommand(application, _commands.terminate());
    await _smartCardInterface.sendCommand(application, _commands.activate());
  }

  Future<void> _blockPins() async {
    var invalidPin = '00000000';
    PinRetries retries = await getRemainingPinTries();
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.pin)) {
      try {
        await _smartCardInterface.sendCommand(
            application, _commands.verifySignaturePin(invalidPin));
      } catch (e) {
        //Ignore
      }
    }
    // ignore: no_leading_underscores_for_local_identifiers
    for (var _ in Iterable.generate(retries.admin)) {
      try {
        await _smartCardInterface.sendCommand(
            application, _commands.verifyAdminPin(invalidPin));
      } catch (e) {
        //Ignore
      }
    }
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
