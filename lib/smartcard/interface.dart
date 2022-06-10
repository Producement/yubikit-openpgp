import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class SmartCardInterface {
  const SmartCardInterface();

// 90 00 OK
  static const _successfulEnd = [144, 0, 10, 79, 75, 10];

  Future<Uint8List> sendCommand(Application application, List<int> input,
      {List<int>? verify}) async {
    if (verify != null) {
      await _sendCommand(verify);
    }
    return await _sendCommand(input);
  }

  Future<Uint8List> _sendCommand(List<int> input, [List<int> accumulatingBytes = const []]) async {
    String command = 'scd apdu ${_hexWithSpaces(input)}';
    var processResult =
        await Process.run('gpg-connect-agent', [command], stdoutEncoding: null);
    List<int> result = processResult.stdout;
    Function eq = const ListEquality().equals;
    final resultStatus =
        result.skip(result.length - _successfulEnd.length).toList();
    final isLongResponse = (resultStatus[0] == 97);
    if (isLongResponse) {
      final processedResult = resultContent(result);
      return _sendCommand([0x00, Instruction.sendRemaining.value, 0x00, 0x00, resultStatus[1]], accumulatingBytes + processedResult);
    } else if (!eq(resultStatus, _successfulEnd)) {
      final errorCode =
          result.skip(result.length - _successfulEnd.length).take(2).toList();
      throw SmartCardException(errorCode[0], errorCode[1]);
    }
    final processedResult = resultContent(result);
    return Uint8List.fromList(accumulatingBytes + processedResult);
  }

  List<int> resultContent(List<int> result) => result.skip(2).take(result.length - 8).toList();

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

  Future<Uint8List> sendApdu(
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
