import boofuzz
from bitstring import BitStream, BitArray
from dataclasses import dataclass
from typing import override, Self

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

