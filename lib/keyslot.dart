enum KeySlot {
  signature,
  encryption,
  authentication,
}

extension KeySlotValues on KeySlot {
  String get value {
    switch (this) {
      case KeySlot.signature:
        return 'SIGNATURE';
      case KeySlot.encryption:
        return 'ENCRYPTION';
      case KeySlot.authentication:
        return 'AUTHENTICATION';
    }
  }

  int get keyId {
    switch (this) {
      case KeySlot.signature:
        return 0xC1;
      case KeySlot.encryption:
        return 0xC2;
      case KeySlot.authentication:
        return 0xC3;
    }
  }

  int get fingerprint {
    switch (this) {
      case KeySlot.signature:
        return 0xC7;
      case KeySlot.encryption:
        return 0xC8;
      case KeySlot.authentication:
        return 0xC9;
    }
  }

  int get genTime {
    switch (this) {
      case KeySlot.signature:
        return 0xCE;
      case KeySlot.encryption:
        return 0xCF;
      case KeySlot.authentication:
        return 0xD0;
    }
  }

  int get uif {
    switch (this) {
      case KeySlot.signature:
        return 0xD6;
      case KeySlot.encryption:
        return 0xD7;
      case KeySlot.authentication:
        return 0xD8;
    }
  }

  List<int> get crt {
    switch (this) {
      case KeySlot.signature:
        return [0xB6, 0x00];
      case KeySlot.encryption:
        return [0xB8, 0x00];
      case KeySlot.authentication:
        return [0xA4, 0x00];
    }
  }
}
