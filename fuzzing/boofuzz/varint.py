import struct

SEGMENT_BITS = 0x7f
CONTINUE_BIT = 0x80

# Note: this doesn't sign numbers (Python numbers are infinite)
# you have to do that yourself
def read_varnum(varnum: bytes, max_len: int) -> int:
    value: int = 0
    position: int = 0
    i: int = 0

    while True:
        current = varnum[i]
        value |= (current & SEGMENT_BITS) << position
        if (current & CONTINUE_BIT) == 0:
            break
        position += 7
        if position >= max_len:
            raise RuntimeError(f"VarInt is too big to read: maximum length {max_len} bits")
        i += 1
    
    return value

def read_varint(varint: bytes) -> int:
    byte_value = struct.pack(">L", read_varnum(varint, 32))
    return struct.unpack(">l", byte_value)[0]

def read_varlong(varlong: bytes) -> int:
    byte_value = struct.pack(">Q", read_varnum(varlong, 64))
    return struct.unpack(">q", byte_value)[0]

def write_varnum(varnum: int, bit_size: int) -> bytes:
    value = bytearray()
    mask = (1 << bit_size) - 1
    varnum_cut = varnum & mask

    while True:
        if (varnum_cut & ~SEGMENT_BITS) == 0:
            value.append(varnum_cut)
            return value
        value.append((varnum_cut & SEGMENT_BITS) | CONTINUE_BIT)
        varnum_cut = (varnum_cut & mask) >> 7

def write_varint(varint: int) -> bytes:
    return write_varnum(varint, 32)

def write_varlong(varlong: int) -> bytes:
    return write_varnum(varlong, 64)