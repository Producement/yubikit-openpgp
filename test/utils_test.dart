import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:yubikit_openpgp/curve.dart';
import 'package:yubikit_openpgp/utils.dart';

void main() {
  test('calculates ec fingerprint', () async {
    final pubKey =
        '40189452D84165788AE29A0CD494D2C7C01EECA5333B5426FEF6D52CD206C91AAE';
    final fingerprint = PGPUtils.calculateECFingerprint(
        BigInt.parse(pubKey, radix: 16), ECCurve.ed25519, 1652084583);
    expect(hex.encode(fingerprint),
        equals('D25515C366D77B8E9B66CD4BAC6B363B0C5A4FBD'.toLowerCase()));
  });

  test('calculates rsa fingerprint', () async {
    final modulus =
        'ANGvy2jusiy/cicp84GMZnOcDRc1MdPHD1aBUVEIvxeEEpk6S6fwhObREEPOHBn5rhx2bm09S+xjAvdxsDkTF5POqPPPKkJfdwX1EWxzKUrgEUHoqyxZEfZDSM1KsIWq8h0X0sv19W/NG0/SeEd0GMR4jSunqq1QU31wU/9kpJg22KzPAtHRcPbc9GZjOi9uzXWji9CKfwH8kRZHr9zXCzG2Q/Y8eeDGzsgLnJ+jKeMp7LjdWWbIz2mmwq+bIQwgnVnC1An/F16YDH7IzAZdtAscgPnmdvn9o7LyKnpIfXNhyI36sax1fIsvwBRsGBrYjn/WdqPktFZuXLPZTvGjZeM=';
    final exponent = Uint8List.fromList([0x01, 0x00, 0x01]);
    final fingerprint = PGPUtils.calculateRSAFingerprint(
        base64Decode(modulus), exponent, 1652084583);
    expect(hex.encode(fingerprint),
        equals('f9c529ad74884a662384b287cef59add4a28b99d'.toLowerCase()));
  });

  test('builds PGP public key packet', () async {
    final pubKeyAsBigInt = BigInt.parse(
        '7421333061992363374626259639439359738434221499360902310111361495942986672053976');

    final timestamp =
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
