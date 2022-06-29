import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/utils.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

/// Smartcard interface implementation that uses gpg-connect-agent to run smartcard commands
/// Usually you want to implement this yourself to use something more suitable
class SmartCardInterface {
  const SmartCardInterface();

  /// 90 00 OK from gpg-connect-agent
  static const _successfulEnd = [144, 0, 10, 79, 75, 10];

  Future<Uint8List> sendCommand(Application application, List<int> input,
      {List<int>? verify}) async {
    final response =
        await (await sendCommands(application, [input], verify: verify)).first;
    if (response is ErrorResponse) {
      throw response.exception;
    } else if (response is SuccessfulResponse) {
      return Uint8List.fromList(response.response);
    } else {
      throw Exception('Response type not supported ${response.runtimeType}');
    }
  }

  Future<Stream<SmartCardResponse>> sendCommands(
      Application application, List<List<int>> input,
      {List<int>? verify}) async {
    if (verify != null) {
      await _sendCommand(verify);
    }
    return Stream.fromFutures(input.map((e) => _sendCommand(e)));
  }

  Future<SmartCardResponse> _sendCommand(List<int> input,
      [List<int> accumulatingBytes = const []]) async {
    final String command = 'scd apdu ${_hexWithSpaces(input)}';
    final processResult =
        await Process.run('gpg-connect-agent', [command], stdoutEncoding: null);
    final List<int> result = processResult.stdout;
    final Function eq = const ListEquality().equals;
    final resultStatus =
        result.skip(result.length - _successfulEnd.length).toList();
    final isLongResponse = (resultStatus[0] == 0x61);
    if (isLongResponse) {
      final processedResult = _resultContent(result);
      return _sendCommand(
          [0x00, Instruction.sendRemaining.value, 0x00, 0x00, 0x00],
          accumulatingBytes + processedResult);
    } else if (!eq(resultStatus, _successfulEnd)) {
      final errorCode =
          result.skip(result.length - _successfulEnd.length).take(2).toList();
      return SmartCardResponse.fromBytes(errorCode.take(2).toList());
    }
    final processedResult = _resultContent(result);
    return SmartCardResponse.fromBytes(accumulatingBytes + processedResult);
  }

  // Result starts with "D " and ends with "90 00 OK". %, CR and LF must be percent encoded, others can be.
  List<int> _resultContent(List<int> result) =>
      PGPUtils.percentUnescape(result.skip(2).take(result.length - 8).toList());

  String _hexWithSpaces(List<int> input) {
    if (input.isEmpty) {
      return '';
    }
    String command = '';
    for (var item in input) {
      command += '${hex.encode([item])} ';
    }
    return command.substring(0, command.length - 1);
  }
}
