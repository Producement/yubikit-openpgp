import 'package:convert/convert.dart';

class SmartCardException implements Exception {
  final int sw1, sw2;

  const SmartCardException(this.sw1, this.sw2);

  SmartCardError getError() {
    switch (hex.encode([sw1, sw2])) {
      case '6285':
        return SmartCardError.doInTerminationState;
      case '6581':
        return SmartCardError.memoryFailure;
      case '6600':
        return SmartCardError.securityIssue;
      case '6700':
        return SmartCardError.wrongLength;
      case '6881':
        return SmartCardError.logicalChannelNotSupported;
      case '6882':
        return SmartCardError.secureMessagingNotSupported;
      case '6883':
        return SmartCardError.lastCommandOfChainExpected;
      case '6884':
        return SmartCardError.commandChainingNotSupported;
      case '6982':
        return SmartCardError.authenticationError;
      case '6983':
        return SmartCardError.authenticationBlocked;
      case '6985':
        return SmartCardError.conditionOfUseNotSatisfied;
      case '6987':
        return SmartCardError.expectedSecureMessagingDosMissing;
      case '6988':
        return SmartCardError.secureMessagingDosIncorrect;
      case '6a80':
        return SmartCardError.incorrectParametersInCommandData;
      case '6a82':
        return SmartCardError.fileOrApplicationNotFound;
      case '6a88':
        return SmartCardError.referencedDataOrDoNotFound;
      case '6b00':
        return SmartCardError.wrongParameters;
      case '6d00':
        return SmartCardError.instructionCodeInvalid;
      case '6e00':
        return SmartCardError.classNotSupported;
      case '6f00':
        return SmartCardError.noPreciseDiagnosis;
    }
    return SmartCardError.unknown;
  }

  @override
  String toString() {
    final type = getError();
    if (type == SmartCardError.unknown) {
      return 'SmartCardException(unknown:${sw1.toRadixString(16)},${sw2.toRadixString(16)})';
    }
    return 'SmartCardException(${type.name})';
  }
}

enum SmartCardError {
  doInTerminationState,
  memoryFailure,
  securityIssue,
  wrongLength,
  logicalChannelNotSupported,
  secureMessagingNotSupported,
  lastCommandOfChainExpected,
  commandChainingNotSupported,
  authenticationError,
  authenticationBlocked,
  conditionOfUseNotSatisfied,
  expectedSecureMessagingDosMissing,
  secureMessagingDosIncorrect,
  incorrectParametersInCommandData,
  fileOrApplicationNotFound,
  referencedDataOrDoNotFound,
  wrongParameters,
  instructionCodeInvalid,
  classNotSupported,
  noPreciseDiagnosis,
  unknown,
}
