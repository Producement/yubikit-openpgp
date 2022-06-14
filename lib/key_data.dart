import 'dart:typed_data';

abstract class KeyData {
  const KeyData();
}

class ECKeyData extends KeyData {
  final Uint8List publicKey;

  const ECKeyData(this.publicKey);
}

class RSAKeyData extends KeyData {
  final Uint8List modulus, exponent;

  const RSAKeyData(this.modulus, this.exponent);
}
