import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

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

  Hash get digest {
    switch (this) {
      case HashAlgorithm.sha256:
        return sha256;
      case HashAlgorithm.sha512:
        return sha512;
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
