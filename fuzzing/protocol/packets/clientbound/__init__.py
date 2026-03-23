import dataclasses
from typing import Self

from fuzzing.models.varint import read_varint


def read_basic_packet(b: bytes, protocol_number: int) -> bytes:
    packet_length_varnum = read_varint(b)
    b = b[packet_length_varnum.length :]

    assert b[0] == protocol_number

    return b[1:]


def read_compressed_packet(b: bytes, protocol_number: int) -> bytes:
    packet_length_varnum = read_varint(b)
    b = b[packet_length_varnum.length :]

    # TODO: Decompress the rest of the packet (b)

    return b


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SetCompression:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
    threshold: int

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self, bytes]:
        b = read_basic_packet(b, 0x3)

        threshold_varnum = read_varint(b)
        b = b[threshold_varnum.length :]

        return (cls(threshold=threshold_varnum.value), b)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class LoginSuccess:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success
    # game_profile: GameProfile

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self, bytes]:
        b = read_compressed_packet(b, 0x2)

        # TODO: Parse game_profile, if you _really_ want. I don't think it's necessary.

        # TODO: Return the actual continuation (after parsing `game_profile`).
        return (cls(), b)
