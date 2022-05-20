import 'package:yubikit_openpgp/interface.dart';
import 'package:yubikit_openpgp/smartcard/interface.dart';

void main(List<String> arguments) async {
  // Directly calls gpg-connect-agent, provide your own implementation!
  final smartCardInterface = SmartCardInterface();
  final openPGPInterface = OpenPGPInterface(smartCardInterface);

  final appVersion = await openPGPInterface.applicationVersion;
  print('Application version: $appVersion');
}
