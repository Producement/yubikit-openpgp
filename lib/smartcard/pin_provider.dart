import 'package:yubikit_openpgp/yubikit_openpgp.dart';

/// Provides pins to the smartcard interface
/// Implement your own version if you don't use default pins
class PinProvider {
  String get adminPin => YubikitOpenPGP.defaultAdminPin;

  String get pin => YubikitOpenPGP.defaultPin;
}
