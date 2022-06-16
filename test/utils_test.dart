import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:yubikit_openpgp/curve.dart';
import 'package:yubikit_openpgp/utils.dart';

void main() {
  test('calculates fingerprint', () async {
    var pubKey =
        '40189452D84165788AE29A0CD494D2C7C01EECA5333B5426FEF6D52CD206C91AAE';
    var fingerprint = PGPUtils.calculateECFingerprint(
        BigInt.parse(pubKey, radix: 16), ECCurve.ed25519, 1652084583);
    expect(hex.encode(fingerprint),
        equals('D25515C366D77B8E9B66CD4BAC6B363B0C5A4FBD'.toLowerCase()));
  });

  test('builds PGP public key packet', () async {
    var pubKeyAsBigInt = BigInt.parse(
        '7421333061992363374626259639439359738434221499360902310111361495942986672053976');

    var timestamp =
        (DateTime.parse('2022-05-05T16:13:58+03:00').millisecondsSinceEpoch /
                1000)
            .round();
    expect(
        PGPUtils.buildECPublicKeyPacket(
            pubKeyAsBigInt, ECCurve.ed25519, timestamp),
        equals(hex.decode(
            '9833046273cd9616092b06010401da470f010107401785a8be6b7d9bfe092e3a1172386c98a498298a44644fbd90ae8fb9c6d31ed8')));
  });

  test('armor', () async {
    final result = PGPUtils.armor(base64.decode(
        'yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA=='));
    expect(result, equals('''-----BEGIN PGP PUBLIC KEY BLOCK-----

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA==
=njUN
-----END PGP PUBLIC KEY BLOCK-----'''));
  });

  test('percent unescaping', () async {
    expect(PGPUtils.percentUnescape([]), equals([]));
    expect(PGPUtils.percentUnescape([0x10, 0x20]), equals([0x10, 0x20]));
    expect(PGPUtils.percentUnescape([0x25, 0x30, 0x41]), equals([0x0A]));
    expect(PGPUtils.percentUnescape([0xFF, 0x25, 0x32, 0x35, 0x00]),
        equals([0xFF, 0x25, 0x00]));
  });

  test('bigint conversion works both ways', () async {
    final num = BigInt.from(1234567890);
    expect(
        PGPUtils.intListToBigInt(PGPUtils.bigIntToUint8List(num)), equals(num));
  });
}
