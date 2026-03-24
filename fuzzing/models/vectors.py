import boofuzz, math
from bitstring import BitStream, BitArray
from dataclasses import dataclass
from typing import override, Self
from fuzzing.models.varint import read_varint, write_varint

@dataclass(frozen=True, slots=True)
class Position:
    """
    Position literal: can be read from binary contents
    """
    x: int
    y: int
    z: int

    @classmethod
    def read(cls, data: bytes) -> tuple[Self, bytes]:
        assert len(data) >= 8
        s = BitStream(data)
        x = s.read('int:26')
        z = s.read('int:26')
        y = s.read('int:12')
        return (cls(x, y, z), data[8:])

_MAX_QUANTIZED_VALUE = 32766.0

def _unpack(value: int) -> float:
    return min(value & 32767, _MAX_QUANTIZED_VALUE) * 2.0 / _MAX_QUANTIZED_VALUE - 1.0

def _pack(value: float) -> int:
    return round((value * 0.5 + 0.5) * _MAX_QUANTIZED_VALUE)

@dataclass(frozen=True, slots=True)
class LpVec3:
    """
    LpVec3 literal: can be read from binary contents
    """
    x: float
    y: float
    z: float

    @classmethod
    def read(cls, data: bytes) -> tuple[Self, bytes]:
        assert len(data) >= 1
        if data[0] == 0:
            return (cls(0.0, 0.0, 0.0), data[1:])
        assert len(data) >= 6
        length = 6
        vec3_bytes = bytes([data[2], data[3], data[4], data[5], data[1], data[0]])
        s = BitStream(vec3_bytes)
        packed_z = s.read('uint:15')
        packed_y = s.read('uint:15')
        packed_x = s.read('uint:15')
        continuation = s.read('bool')
        scale = s.read('uint:2')
        if continuation:
            scale_msb = read_varint(data[6:])
            scale |= scale_msb.value << 2
            length += scale_msb.length
        x = _unpack(packed_x) * scale
        y = _unpack(packed_y) * scale
        z = _unpack(packed_z) * scale
        return (cls(x, y, z), data[length:])
    
    def write(self) -> bytes:
        max_coord = max(abs(self.x), abs(self.y), abs(self.z))
        if max_coord < 3.051944088384301e-5:
            return b'\x00'
        else:
            scale = int(math.ceil(max_coord))
            continuation = (scale & 3) != scale
            packed_x = _pack(self.x / scale)
            packed_y = _pack(self.y / scale)
            packed_z = _pack(self.z / scale)
            s = BitArray()
            s.append(f"uint:15={packed_z & 0x7FFF}")
            s.append(f"uint:15={packed_y & 0x7FFF}")
            s.append(f"uint:15={packed_x & 0x7FFF}")
            s.append(f"bool={continuation}")
            s.append(f"uint:2={scale & 3}")
            if continuation:
                s.append(write_varint(scale >> 2))
            final = s.tobytes()
            return bytes([final[5], final[4], final[0], final[1], final[2], final[3], *final[6:]])

class PositionBlock(boofuzz.FuzzableBlock):
    """Position primitive
    :param name: Name, for referencing later
    :param default: Default position
    :param fuzzable: Enable/Disable fuzzing for this primitive
    """

    @override
    def __init__(
            self,
            name: str | None = None,
            default: Position = Position(0, 0, 0),
            fuzzable: bool = True,
            *args,
            **kwargs
    ):
        super().__init__(
            name=name,
            children=(
                boofuzz.BitField("x", default.x, 26, endian=boofuzz.BIG_ENDIAN, signed=True),
                boofuzz.BitField("z", default.z, 26, endian=boofuzz.BIG_ENDIAN, signed=True),
                boofuzz.BitField("y", default.y, 12, endian=boofuzz.BIG_ENDIAN, signed=True)
            ),
            fuzzable=fuzzable,
            *args,
            **kwargs
        )
    
    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        s = BitStream(data)
        out = BitArray()
        s.read('bits:6')
        out.append(s.read('bits:26'))
        s.read('bits:6')
        out.append(s.read('bits:26'))
        s.read('bits:4')
        out.append(s.read('bits:12'))
        return out.tobytes()

