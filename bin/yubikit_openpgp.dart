import 'package:yubikit_openpgp/smartcard/interface.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main(List<String> arguments) async {
  // Directly calls gpg-connect-agent, provide your own implementation!
  final smartCardInterface = SmartCardInterface();
  final openPGPInterface = YubikitOpenPGP(smartCardInterface);

  final appVersion = await openPGPInterface.applicationVersion;
  print('Application version: $appVersion');
}
