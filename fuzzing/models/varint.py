import dataclasses
import struct

SEGMENT_BITS = 0x7F
CONTINUE_BIT = 0x80


@dataclasses.dataclass(frozen=True, slots=True)
class VarNumFromBytes:
    value: int
    length: int


# Note: this doesn't sign numbers (Python numbers are infinite)
# you have to do that yourself
def read_varnum(varnum: bytes, max_len: int) -> VarNumFromBytes:
    value = 0
    position = 0
    length = 0

    while True:
        current = varnum[length]
        value |= (current & SEGMENT_BITS) << position
        if (current & CONTINUE_BIT) == 0:
            break
        position += 7
        if position >= max_len:
            raise RuntimeError(
                f"VarInt is too big to read: maximum length {max_len} bits"
            )
        length += 1

    return VarNumFromBytes(value, length + 1)


def read_varint(b: bytes) -> VarNumFromBytes:
    varnum = read_varnum(b, 32)
    byte_value = struct.pack(">L", varnum.value)
    return VarNumFromBytes(struct.unpack(">l", byte_value)[0], varnum.length)


def read_varlong(b: bytes) -> VarNumFromBytes:
    varnum = read_varnum(b, 64)
    byte_value = struct.pack(">Q", varnum.value)
    return VarNumFromBytes(struct.unpack(">q", byte_value)[0], varnum.length)


def write_varnum(varnum: int, bit_size: int) -> bytes:
    value = bytearray()
    mask = (1 << bit_size) - 1
    varnum_cut = varnum & mask

    while True:
        if (varnum_cut & ~SEGMENT_BITS) == 0:
            value.append(varnum_cut)
            return bytes(value)
        value.append((varnum_cut & SEGMENT_BITS) | CONTINUE_BIT)
        varnum_cut = (varnum_cut & mask) >> 7


def write_varint(varint: int) -> bytes:
    return write_varnum(varint, 32)


def write_varlong(varlong: int) -> bytes:
    return write_varnum(varlong, 64)
