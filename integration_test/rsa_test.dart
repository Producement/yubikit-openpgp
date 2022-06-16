import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:test/test.dart';
import 'package:yubikit_openpgp/utils.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main() {
  final smartCardInterface = SmartCardInterface();
  final pinProvider = PinProvider();
  final openPGPInterface = YubikitOpenPGP(smartCardInterface, pinProvider);
  final cipher = PKCS1Encoding(RSAEngine());

  test('encrypts and decrypts with RSA', () async {
    final key = await openPGPInterface.getPublicKey(KeySlot.encryption);
    if (key is! RSAKeyData) {
      fail('Not RSA key: ${key.runtimeType}');
    }
    final plaintext = Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    cipher.init(
        true,
        PublicKeyParameter<RSAPublicKey>(RSAPublicKey(
            PGPUtils.intListToBigInt(key.modulus),
            PGPUtils.intListToBigInt(key.exponent))));
    final encryptedKey = cipher.process(plaintext);
    final decryptedKey = await openPGPInterface.decipher(encryptedKey);
    expect(plaintext, equals(decryptedKey));
  });
}