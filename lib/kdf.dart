import 'package:crypto/crypto.dart';

import 'hash_algorithm.dart';
import 'yubikit_openpgp.dart';

enum KdfAlgorithm {
  none,
  kdfItersaltedS2k,
}

extension KdfAlgorithmValue on KdfAlgorithm {
  int get value {
    switch (this) {
      case KdfAlgorithm.none:
        return 0x00;
      case KdfAlgorithm.kdfItersaltedS2k:
        return 0x03;
    }
  }
}

class KdfData {
  final KdfAlgorithm algorithm;
  final HashAlgorithm hashAlgorithm;
  final int iterationCount;
  final Iterable<int>? pw1SaltBytes;
  final Iterable<int> pw3SaltBytes;

  const KdfData(this.algorithm, this.hashAlgorithm, this.iterationCount,
      this.pw1SaltBytes, this.pw3SaltBytes);

  factory KdfData.parse(List<int> data) {
    if (data[0] == 0x81 && data[1] == 0x01 && data[2] == 0x00) {
      return KdfData(KdfAlgorithm.none, HashAlgorithm.sha256, 0, null, []);
    }
    //TODO: support other KDF algorithms
    throw Exception('KDF is not implemented properly yet.');
  }

  Iterable<int> process(int pw, Iterable<int> pin) {
    if (algorithm == KdfAlgorithm.none) {
      return pin;
    } else if (algorithm == KdfAlgorithm.kdfItersaltedS2k) {
      late Iterable<int> salt;
      if (pw == YubikitOpenPGP.pw1_81) {
        salt = pw1SaltBytes!;
      } else if (pw == YubikitOpenPGP.pw3_83) {
        salt = pw1SaltBytes ?? pw3SaltBytes;
      }
      return kdfItersaltedS2k(pin, salt);
    }
    throw Exception('Algorithm not supported!');
  }

  Iterable<int> kdfItersaltedS2k(Iterable<int> pin, Iterable<int> salt) {
    Iterable<int> data = salt.followedBy(pin);
    Hash digest = hashAlgorithm.digest;
    List<int> input = List.empty();
    int trailingBytes = iterationCount % data.length;
    int dataCount = ((iterationCount - trailingBytes) / data.length) as int;
    Iterable<int> trailing = data.skip(trailingBytes);
    for (int i = 0; i < dataCount; i++) {
      input.addAll(data);
    }
    input.addAll(trailing);
    return digest.convert(input).bytes;
  }
}
