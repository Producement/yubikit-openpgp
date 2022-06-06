import 'package:convert/convert.dart';

enum Application {
  otp,
  management,
  openpgp,
  oath,
  piv,
  fido,
  hsmauth,
}

extension ApplicationValue on Application {
  List<int> get value {
    switch (this) {
      case Application.otp:
        return hex.decode('a0000005272001');
      case Application.management:
        return hex.decode('a000000527471117');
      case Application.openpgp:
        return hex.decode('d27600012401');
      case Application.oath:
        return hex.decode('a0000005272101');
      case Application.piv:
        return hex.decode('a000000308');
      case Application.fido:
        return hex.decode('a0000006472f0001');
      case Application.hsmauth:
        return hex.decode('a000000527210701');
    }
  }
}
