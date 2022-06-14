import 'package:cryptography/cryptography.dart';
import 'package:jwk/jwk.dart';

abstract class KeyData {
  const KeyData();

  Jwk toJwk();
}

class ECKeyData extends KeyData {
  final List<int> publicKey;
  final KeyPairType type;

  const ECKeyData(this.publicKey, this.type);

  @override
  Jwk toJwk() {
    return Jwk.fromPublicKey(SimplePublicKey(publicKey, type: type));
  }
}

class RSAKeyData extends KeyData {
  final List<int> modulus, exponent;

  const RSAKeyData(this.modulus, this.exponent);

  @override
  Jwk toJwk() {
    return Jwk.fromPublicKey(RsaPublicKey(e: exponent, n: modulus));
  }
}
