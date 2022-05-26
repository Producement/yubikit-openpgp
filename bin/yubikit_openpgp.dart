import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/smartcard/interface.dart';
import 'package:yubikit_openpgp/smartcard/pin_provider.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main(List<String> arguments) async {
  // Directly calls gpg-connect-agent, provide your own implementation!
  final smartCardInterface = SmartCardInterface();
  final pinProvider = PinProvider();
  final openPGPInterface = YubikitOpenPGP(smartCardInterface, pinProvider);

  final appVersion = await openPGPInterface.applicationVersion;
  print('Application version: $appVersion');

  final ecPublicKey = await openPGPInterface.getECPublicKey(KeySlot.encryption);
  print('Encryption public key: ${hex.encode(ecPublicKey ?? [])}');

  if (ecPublicKey != null) {
    final sharedSecret = await openPGPInterface.ecSharedSecret(ecPublicKey);
    print('Shared secret: ${hex.encode(sharedSecret)}');
  }
}
