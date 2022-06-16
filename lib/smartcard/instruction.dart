import 'dart:typed_data';

enum Instruction {
  getData,
  getVersion,
  setPinRetries,
  verify,
  terminate,
  activate,
  generateAsym,
  putData,
  putDataOdd,
  getAttestation,
  sendRemaining,
  selectData,
  performSecurityOperation,
}

extension InstructionValue on Instruction {
  int get value {
    switch (this) {
      case Instruction.getData:
        return 0xCA;
      case Instruction.getVersion:
        return 0xF1;
      case Instruction.setPinRetries:
        return 0xF2;
      case Instruction.verify:
        return 0x20;
      case Instruction.terminate:
        return 0xE6;
      case Instruction.activate:
        return 0x44;
      case Instruction.generateAsym:
        return 0x47;
      case Instruction.putData:
        return 0xDA;
      case Instruction.putDataOdd:
        return 0xDB;
      case Instruction.getAttestation:
        return 0xFB;
      case Instruction.sendRemaining:
        return 0xC0;
      case Instruction.selectData:
        return 0xA5;
      case Instruction.performSecurityOperation:
        return 0x2A;
    }
  }

  Uint8List apdu(int cla, int p1, int p2, List<int> data) {
    if (data.isNotEmpty) {
      if (data.length > 255) {
        return Uint8List.fromList([
              cla,
              value,
              p1,
              p2,
              0x00,
              data.length >> 8,
              data.length & 0xFF
            ] +
            data);
      }
      return Uint8List.fromList([cla, value, p1, p2, data.length] + data);
    }
    return Uint8List.fromList([cla, value, p1, p2]);
  }
}
