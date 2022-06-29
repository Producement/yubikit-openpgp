import 'package:cryptography/cryptography.dart';
import 'package:jwk/jwk.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

import 'tlv.dart';

abstract class KeyData {
  final KeySlot slot;

  const KeyData(this.slot);

  Jwk toJwk() {
    return _fromPublicKey(toPublicKey(), slot);
  }

  PublicKey toPublicKey();

  factory KeyData.fromBytes(List<int> response, KeySlot slot) {
    final data = TlvData.parse(response).get(0x7F49);
    if (data.hasValue(0x86)) {
      return ECKeyData.fromBytes(response, slot);
    } else {
      return RSAKeyData.fromBytes(response, slot);
    }
  }

  Jwk _fromPublicKey(PublicKey publicKey, KeySlot keySlot) {
    final use = KeySlot.signature == keySlot ? 'sig' : 'enc';
    if (publicKey is EcPublicKey) {
      final crv = const <KeyPairType, String>{
        KeyPairType.p256: 'P-256',
        KeyPairType.p384: 'P-384',
        KeyPairType.p521: 'P-521',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          x: publicKey.x,
          use: use,
        );
      }
    } else if (publicKey is SimplePublicKey) {
      final crv = <KeyPairType, String>{
        KeyPairType.ed25519: 'Ed25519',
        KeyPairType.x25519: 'X25519',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'OKP',
          crv: crv,
          x: publicKey.bytes,
          use: use,
        );
      }
    } else if (publicKey is RsaPublicKey) {
      return Jwk(
        kty: 'RSA',
        e: publicKey.e,
        n: publicKey.n,
        use: use,
      );
    }
    throw ArgumentError.value(publicKey);
  }

  @override
  String toString() => String.fromCharCodes(toJwk().toUtf8());

  @override
  int get hashCode => toJwk().hashCode;

  @override
  bool operator ==(other) => other is KeyData && other.toJwk() == toJwk();
}

class ECKeyData extends KeyData {
  final List<int> publicKey;

  const ECKeyData(this.publicKey, KeySlot slot) : super(slot);

  factory ECKeyData.fromBytes(List<int> response, KeySlot slot) {
    final data = TlvData.parse(response).get(0x7F49);
    final publicKey = data.getValue(0x86);
    return ECKeyData(publicKey, slot);
  }

  @override
  Jwk toJwk() {
    final type =
        slot == KeySlot.signature ? KeyPairType.ed25519 : KeyPairType.x25519;
    return _fromPublicKey(SimplePublicKey(publicKey, type: type), slot);
  }

  @override
  PublicKey toPublicKey() {
    final type =
        slot == KeySlot.signature ? KeyPairType.ed25519 : KeyPairType.x25519;
    return SimplePublicKey(publicKey, type: type);
  }
}

class RSAKeyData extends KeyData {
  final List<int> modulus, exponent;

  const RSAKeyData(this.modulus, this.exponent, KeySlot slot) : super(slot);

  factory RSAKeyData.fromBytes(List<int> response, KeySlot slot) {
    final data = TlvData.parse(response).get(0x7F49);
    final modulus = data.getValue(0x81);
    final exponent = data.getValue(0x82);
    return RSAKeyData(modulus, exponent, slot);
  }

  @override
  PublicKey toPublicKey() => RsaPublicKey(e: exponent, n: modulus);
}
