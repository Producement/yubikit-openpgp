import 'package:test/test.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main() {
  test('ec key data from bytes', () async {
    final keyBytes = [0x7F, 0x49, 0x03, 0x86, 0x01, 0x01];
    final keyData = KeyData.fromBytes(keyBytes, KeySlot.encryption);
    expect(keyData.slot, equals(KeySlot.encryption));
    expect(keyData.runtimeType, equals(ECKeyData));
    expect((keyData as ECKeyData).publicKey, equals([0x01]));
    expect(keyData.toJwk().toJson(),
        equals({'crv': 'X25519', 'kty': 'OKP', 'use': 'enc', 'x': 'AQ=='}));
  });

  test('rsa key data from bytes', () async {
    final keyBytes = [0x7F, 0x49, 0x06, 0x81, 0x01, 0x01, 0x82, 0x01, 0x02];
    final keyData = KeyData.fromBytes(keyBytes, KeySlot.encryption);
    expect(keyData.slot, equals(KeySlot.encryption));
    expect(keyData.runtimeType, equals(RSAKeyData));
    expect((keyData as RSAKeyData).modulus, equals([0x01]));
    expect(keyData.exponent, equals([0x02]));
    expect(keyData.toJwk().toJson(),
        equals({'e': 'Ag==', 'kty': 'RSA', 'n': 'AQ==', 'use': 'enc'}));
  });
}
