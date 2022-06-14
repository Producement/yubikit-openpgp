abstract class KeyData {
  const KeyData();
}

class ECKeyData extends KeyData {
  final List<int> publicKey;

  const ECKeyData(this.publicKey);
}

class RSAKeyData extends KeyData {
  final List<int> modulus, exponent;

  const RSAKeyData(this.modulus, this.exponent);
}
