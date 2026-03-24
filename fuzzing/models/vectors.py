import math
from dataclasses import dataclass
from typing import Self, override

import boofuzz
from bitstring import BitArray, BitStream

from fuzzing.models.varint import VarInt


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
        x = s.read("int:26")
        z = s.read("int:26")
        y = s.read("int:12")
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
        rem = data[6:]
        vec3_bytes = bytes([data[2], data[3], data[4], data[5], data[1], data[0]])
        s = BitStream(vec3_bytes)
        packed_z = s.read("uint:15")
        packed_y = s.read("uint:15")
        packed_x = s.read("uint:15")
        continuation = s.read("bool")
        scale = s.read("uint:2")
        if continuation:
            scale_msb, rem = VarInt.read(rem)
            scale |= scale_msb << 2
        x = _unpack(packed_x) * scale
        y = _unpack(packed_y) * scale
        z = _unpack(packed_z) * scale
        return (cls(x, y, z), rem)

    def write(self) -> bytes:
        max_coord = max(abs(self.x), abs(self.y), abs(self.z))
        if max_coord < 3.051944088384301e-5:
            return b"\x00"
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
                s.append(VarInt(scale >> 2).write())
            final = s.tobytes()
            return bytes(
                [final[5], final[4], final[0], final[1], final[2], final[3], *final[6:]]
            )


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
        **kwargs,
    ):
        super().__init__(
            name=name,
            children=(
                boofuzz.BitField(
                    "x", default.x, 26, endian=boofuzz.BIG_ENDIAN, signed=True
                ),
                boofuzz.BitField(
                    "z", default.z, 26, endian=boofuzz.BIG_ENDIAN, signed=True
                ),
                boofuzz.BitField(
                    "y", default.y, 12, endian=boofuzz.BIG_ENDIAN, signed=True
                ),
            ),
            fuzzable=fuzzable,
            *args,
            **kwargs,
        )

    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        s = BitStream(data)
        out = BitArray()
        s.read("bits:6")
        out.append(s.read("bits:26"))
        s.read("bits:6")
        out.append(s.read("bits:26"))
        s.read("bits:4")
        out.append(s.read("bits:12"))
        return out.tobytes()


class LpVec3Block(boofuzz.FuzzableBlock):
    """LpVec3 Primitive
    :param name: Name, for referencing later
    :param default: Default vector
    :param fuzzable: Enable/Disable fuzzing for this primitive
    """

    @override
    def __init__(
        self,
        name: str | None = None,
        default: LpVec3 = LpVec3(0, 0, 0),
        fuzzable: bool = True,
        *args,
        **kwargs,
    ):
        max_coord = max(abs(default.x), abs(default.y), abs(default.z))
        scale = int(math.ceil(max_coord))
        x = 0 if max_coord == 0 else _pack(default.x / scale)
        y = 0 if max_coord == 0 else _pack(default.y / scale)
        z = 0 if max_coord == 0 else _pack(default.z / scale)
        super().__init__(
            name=name,
            children=(
                boofuzz.BitField("x", x, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("y", y, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("z", z, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("scale", scale, 31, endian=boofuzz.BIG_ENDIAN),
            ),
            fuzzable=fuzzable,
            *args,
            **kwargs,
        )

    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        s = BitStream(data)
        s.read("bits:1")
        x = s.read("uint:15")
        s.read("bits:1")
        y = s.read("uint:15")
        s.read("bits:1")
        z = s.read("uint:15")
        s.read("bits:1")
        scale = s.read("uint:31")
        vec = LpVec3(_unpack(x) * scale, _unpack(y) * scale, _unpack(z) * scale)
        return vec.write()
