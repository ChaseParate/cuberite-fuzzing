import math
from typing import override

import boofuzz
from bitstring import BitArray, BitStream

from fuzzing.models.vectors import LpVec3, Position


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
        **kwargs,
    ):
        super().__init__(
            name=name,
            children=(
                boofuzz.BitField(
                    "x",
                    default.x,
                    26,
                    endian=boofuzz.BIG_ENDIAN,
                    signed=True,
                ),
                boofuzz.BitField(
                    "y",
                    default.y,
                    12,
                    endian=boofuzz.BIG_ENDIAN,
                    signed=True,
                ),
                boofuzz.BitField(
                    "z",
                    default.z,
                    26,
                    endian=boofuzz.BIG_ENDIAN,
                    signed=True,
                ),
            ),
            fuzzable=fuzzable,
            **kwargs,
        )

    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        s = BitStream(data)
        out = BitArray()
        s.read("bits:6")
        out.append(s.read("bits:26"))
        s.read("bits:4")
        out.append(s.read("bits:12"))
        s.read("bits:6")
        out.append(s.read("bits:26"))
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
        **kwargs,
    ):
        max_coord = max(abs(default.x), abs(default.y), abs(default.z))
        scale = int(math.ceil(max_coord))
        x = 0 if max_coord == 0 else LpVec3._pack(default.x / scale)
        y = 0 if max_coord == 0 else LpVec3._pack(default.y / scale)
        z = 0 if max_coord == 0 else LpVec3._pack(default.z / scale)
        super().__init__(
            name=name,
            children=(
                boofuzz.BitField("x", x, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("y", y, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("z", z, 15, endian=boofuzz.BIG_ENDIAN),
                boofuzz.BitField("scale", scale, 31, endian=boofuzz.BIG_ENDIAN),
            ),
            fuzzable=fuzzable,
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
        vec = LpVec3(
            LpVec3._unpack(x) * scale,
            LpVec3._unpack(y) * scale,
            LpVec3._unpack(z) * scale,
        )
        return vec.write()
