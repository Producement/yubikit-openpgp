import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

enum HashAlgorithm {
  sha256,
  sha512,
}

extension HashAlgorithmValue on HashAlgorithm {
  int get value {
    switch (this) {
      case HashAlgorithm.sha256:
        return 0x08;
      case HashAlgorithm.sha512:
        return 0x0A;
    }
  }

  cryptography.HashAlgorithm get digest {
    switch (this) {
      case HashAlgorithm.sha256:
        return cryptography.Sha256();
      case HashAlgorithm.sha512:
        return cryptography.Sha512();
    }
  }

  List<int> get oid {
    switch (this) {
      case HashAlgorithm.sha256:
        return hex.decode('608648016503040201');
      case HashAlgorithm.sha512:
        return hex.decode('608648016503040203');
    }
  }
}
