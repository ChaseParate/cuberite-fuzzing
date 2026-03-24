import struct
from dataclasses import dataclass
from typing import Self, override

SEGMENT_BITS = 0x7F
CONTINUE_BIT = 0x80


@dataclass(frozen=True, slots=True)
class VarNumFromBytes:
    value: int
    length: int


class VarNum(int):
    # Note: this doesn't sign numbers (Python numbers are infinite)
    # you have to do that yourself
    @staticmethod
    def read(data: bytes, max_len: int) -> tuple[Self, bytes]:
        value = 0
        position = 0
        length = 0

        while True:
            current = data[length]
            value |= (current & SEGMENT_BITS) << position
            if (current & CONTINUE_BIT) == 0:
                break
            position += 7
            if position >= max_len:
                raise RuntimeError(
                    f"VarInt is too big to read: maximum length {max_len} bits"
                )
            length += 1

        return (value, data[length + 1 :])

    def _write(self, bit_size: int) -> bytes:
        value = bytearray()
        mask = (1 << bit_size) - 1
        varnum_cut = self & mask

        while True:
            if (varnum_cut & ~SEGMENT_BITS) == 0:
                value.append(varnum_cut)
                return bytes(value)
            value.append((varnum_cut & SEGMENT_BITS) | CONTINUE_BIT)
            varnum_cut = (varnum_cut & mask) >> 7


class VarInt(VarNum):
    @override
    @staticmethod
    def read(data: bytes) -> tuple[Self, bytes]:
        val, rest = VarNum.read(data, 32)
        byte_val = struct.pack(">L", val)
        return (struct.unpack(">l", byte_val)[0], rest)

    def write(self) -> bytes:
        return VarNum._write(self, 32)


class VarLong(VarNum):
    @override
    @staticmethod
    def read(data: bytes) -> tuple[Self, bytes]:
        val, rest = VarNum.read(data, 64)
        byte_val = struct.pack(">Q", val)
        return (struct.unpack(">q", byte_val)[0], rest)

    def write(self) -> bytes:
        return VarNum._write(self, 64)
