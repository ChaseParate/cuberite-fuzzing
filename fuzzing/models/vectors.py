import math
from dataclasses import dataclass
from typing import Self

from bitstring import BitStream, pack

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
        y = s.read("int:12")
        z = s.read("int:26")

        return (cls(x, y, z), data[8:])

    def write(self) -> bytes:
        s = pack("int:26, int:12, int:26", self.x, self.y, self.z)
        return s.tobytes()


_MAX_QUANTIZED_VALUE = 32766.0


@dataclass(frozen=True, slots=True)
class LpVec3:
    """
    LpVec3 literal: can be read from binary contents
    """

    x: float
    y: float
    z: float

    @staticmethod
    def _unpack(value: int) -> float:
        return (
            min(value & 32767, _MAX_QUANTIZED_VALUE) * 2.0 / _MAX_QUANTIZED_VALUE - 1.0
        )

    @staticmethod
    def _pack(value: float) -> int:
        return round((value * 0.5 + 0.5) * _MAX_QUANTIZED_VALUE)

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
        x = LpVec3._unpack(packed_x) * scale
        y = LpVec3._unpack(packed_y) * scale
        z = LpVec3._unpack(packed_z) * scale
        return (cls(x, y, z), rem)

    def write(self) -> bytes:
        max_coord = max(abs(self.x), abs(self.y), abs(self.z))
        if max_coord < 3.051944088384301e-5:
            return b"\x00"

        scale = int(math.ceil(max_coord))
        continuation = (scale & 3) != scale
        packed_x = LpVec3._pack(self.x / scale)
        packed_y = LpVec3._pack(self.y / scale)
        packed_z = LpVec3._pack(self.z / scale)
        s = pack(
            "uint:15, uint:15, uint:15, bool, uint:2",
            packed_z & 0x7FFF,
            packed_y & 0x7FFF,
            packed_x & 0x7FFF,
            continuation,
            scale & 3,
        )
        if continuation:
            s.append(VarInt(scale >> 2).write())

        final = s.tobytes()
        return bytes(
            [final[5], final[4], final[0], final[1], final[2], final[3], *final[6:]]
        )
