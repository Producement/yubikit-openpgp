import 'package:yubikit_openpgp/yubikit_openpgp.dart';

abstract class SmartCardResponse {
  const SmartCardResponse._();

  factory SmartCardResponse.fromBytes(List<int> response) {
    if (response.length == 2) {
      return ErrorResponse(response[0], response[1]);
    } else {
      return SuccessfulResponse(response);
    }
  }
}

class SuccessfulResponse extends SmartCardResponse {
  final List<int> response;

  const SuccessfulResponse(this.response) : super._();
}

class ErrorResponse extends SmartCardResponse {
  final int sw1, sw2;

  const ErrorResponse(this.sw1, this.sw2) : super._();

  SmartCardError get error => getSmartCardError(sw1, sw2);

  SmartCardException get exception => SmartCardException(sw1, sw2);
}
