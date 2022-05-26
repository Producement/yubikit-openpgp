import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class PinProvider {
  String get adminPin => YubikitOpenPGP.defaultAdminPin;

  String get pin => YubikitOpenPGP.defaultPin;
}
