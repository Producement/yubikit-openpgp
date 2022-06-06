import 'dart:io';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class SmartCardInterface {
  const SmartCardInterface();

// 90 00 OK
  static const _successfulEnd = [144, 0, 10, 79, 75, 10];

  Future<List<int>> sendCommand(Application application, List<int> input,
      {List<int>? verify}) async {
    if (verify != null) {
      await _sendCommand(verify);
    }
    return await _sendCommand(input);
  }

  Future<List<int>> _sendCommand(List<int> input) async {
    String command = 'scd apdu ${_hexWithSpaces(input)}';
    var processResult =
        await Process.run('gpg-connect-agent', [command], stdoutEncoding: null);
    List<int> result = processResult.stdout;
    Function eq = const ListEquality().equals;
    if (!eq(result.skip(result.length - _successfulEnd.length).toList(),
        _successfulEnd)) {
      final errorCode =
          result.skip(result.length - _successfulEnd.length).take(2).toList();
      throw SmartCardException(errorCode[0], errorCode[1]);
    }
    final processedResult = result.skip(2).take(result.length - 8).toList();
    return processedResult;
  }

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

  Future<List<int>> sendApdu(
      int cla, Instruction instruction, int p1, int p2, List<int> data,
      {List<int>? verify}) async {
    if (data.isNotEmpty) {
      final command = [cla, instruction.value, p1, p2, data.length] + data;
      return sendCommand(
        Application.openpgp,
        command,
        verify: verify,
      );
    } else {
      return sendCommand(Application.openpgp, [cla, instruction.value, p1, p2],
          verify: verify);
    }
  }
}
