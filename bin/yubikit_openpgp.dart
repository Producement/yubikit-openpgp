import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main(List<String> arguments) async {
  // Directly calls gpg-connect-agent, provide your own implementation!
  final smartCardInterface = SmartCardInterface();
  final pinProvider = PinProvider();
  final openPGPInterface = YubikitOpenPGP(smartCardInterface, pinProvider);

  final publicKey = await openPGPInterface.getPublicKey(KeySlot.signature);
  if (publicKey is ECKeyData) {
    print('Encryption EC public key: ${hex.encode(publicKey.publicKey)}');
  } else if (publicKey is RSAKeyData) {
    print(
        'Encryption RSA public key modulus: ${hex.encode(publicKey.modulus)} exponent: ${hex.encode(publicKey.exponent)}');
  }

  if (publicKey is ECKeyData) {
    final sharedSecret =
        await openPGPInterface.ecSharedSecret(publicKey.publicKey);
    print('Shared secret: ${hex.encode(sharedSecret)}');
  }
}