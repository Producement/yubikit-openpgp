import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/dart.dart';
import 'package:meta/meta.dart';

import 'curve.dart';

class PGPUtils {
  static const sha1 = DartSha1();

  static Uint8List calculateECFingerprint(BigInt publicKey, ECCurve curve,
      [@visibleForTesting int? timestamp]) {
    return Uint8List.fromList(sha1
        .hashSync(buildECPublicKeyPacket(publicKey, curve, timestamp, 0x99))
        .bytes);
  }

  static Uint8List calculateRSAFingerprint(
      List<int> modulus, List<int> exponent,
      [@visibleForTesting int? timestamp]) {
    return Uint8List.fromList(sha1
        .hashSync(buildRSAPublicKeyPacket(modulus, exponent, timestamp, 0x99))
        .bytes);
  }

  @visibleForTesting
  static Uint8List buildRSAPublicKeyPacket(
      List<int> modulus, List<int> exponent,
      [@visibleForTesting int? timestamp, @visibleForTesting int? type]) {
    final List<int> encoded =
        _timestampAndVersion(0x04, timestamp) + _mpi(modulus) + _mpi(exponent);
    type ??= encoded.length >> 8 == 0 ? 0x98 : 0x99;
    return Uint8List.fromList(
        [type] + (type == 0x99 ? _mpi(encoded) : [encoded.length] + encoded));
  }

  static List<int> _mpi(List<int> number) {
    return [number.length >> 8, number.length & 0xFF] + number;
  }

  @visibleForTesting
  static Uint8List buildECPublicKeyPacket(BigInt publicKey, ECCurve curve,
      [int? timestamp, int? type]) {
    final List<int> encoded = _timestampAndVersion(0x04, timestamp) +
        _curve(curve) +
        _keyMaterial(publicKey);
    type ??= encoded.length >> 8 == 0 ? 0x98 : 0x99;
    return Uint8List.fromList(
        [type] + (type == 0x99 ? _mpi(encoded) : [encoded.length] + encoded));
  }

  static Uint8List _timestampAndVersion(int version, int? timestamp) {
    timestamp ??= (DateTime.now().millisecondsSinceEpoch / 1000).round();
    final timestampBytes = ByteData(4)..setInt32(0, timestamp);
    return Uint8List.fromList([version] + timestampBytes.buffer.asUint8List());
  }

  static Uint8List _curve(ECCurve curve) {
    return Uint8List.fromList([curve.algorithm, curve.oid.length] + curve.oid);
  }

  static Uint8List _keyMaterial(BigInt key) {
    return Uint8List.fromList(
        [key.bitLength >> 8, key.bitLength & 0xFF] + bigIntToUint8List(key));
  }

  static String armor(List<int> packet) {
    final content = base64Encode(packet);
    return '''-----BEGIN PGP PUBLIC KEY BLOCK-----

$content
=${base64Encode(_crc24(packet))}
-----END PGP PUBLIC KEY BLOCK-----''';
  }

  static List<int> _crc24(List<int> octets) {
    int crc = 0xB704CE;
    for (var octet in octets) {
      crc ^= octet << 16;
      for (var i = 0; i < 8; i++) {
        crc <<= 1;
        if (crc & 0x1000000 != 0) {
          crc ^= 0x1864CFB;
        }
      }
    }
    return (ByteData(4)..setUint32(0, crc & 0xFFFFFF)).buffer.asUint8List(1);
  }

  static Uint8List bigIntToUint8List(BigInt bigInt) =>
      _bigIntToByteData(bigInt).buffer.asUint8List();

  static ByteData _bigIntToByteData(BigInt bigInt) {
    final data = ByteData((bigInt.bitLength / 8).ceil());

    for (var i = 1; i <= data.lengthInBytes; i++) {
      data.setUint8(data.lengthInBytes - i, bigInt.toUnsigned(8).toInt());
      bigInt = bigInt >> 8;
    }

    return data;
  }

  static BigInt intListToBigInt(List<int> bytes) {
    return BigInt.parse(hex.encode(bytes), radix: 16);
  }

  static List<int> percentUnescape(List<int> result) {
    final unescapedResult = <int>[];
    result.forEachIndexed((index, element) {
      if (index > 1 && result[index - 2] == 0x25) {
        //Bactrack last two inserts
        unescapedResult
          ..removeLast()
          ..removeLast();
        unescapedResult.add(_hexCharPairToByte(
            utf8.decode([result[index - 1], result[index]]), 0));
      } else {
        unescapedResult.add(element);
      }
    });
    return unescapedResult;
  }

  static int _hexCharPairToByte(String s, int pos) {
    int byte = 0;
    for (int i = 0; i < 2; i++) {
      var charCode = s.codeUnitAt(pos + i);
      if (0x30 <= charCode && charCode <= 0x39) {
        byte = byte * 16 + charCode - 0x30;
      } else {
        // Check ranges A-F (0x41-0x46) and a-f (0x61-0x66).
        charCode |= 0x20;
        if (0x61 <= charCode && charCode <= 0x66) {
          byte = byte * 16 + charCode - 0x57;
        } else {
          throw ArgumentError('Invalid URL encoding');
        }
      }
    }
    return byte;
  }
}
