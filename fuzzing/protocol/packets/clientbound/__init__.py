import dataclasses, zlib
from typing import Self

from fuzzing.models.varint import read_varint


def read_basic_packet(b: bytes, protocol_number: int) -> tuple[bytes, bool]:
    init_b = b
    try:
        packet_length_varnum = read_varint(b)
    except IndexError:
        return (init_b, False)
    
    b = b[packet_length_varnum.length :]

    if b[0] == protocol_number:
        return (b[1:], True)
    else:
        return (init_b, False)

def read_string(b: bytes) -> tuple[str, bytes]:
    string_length_varnum = read_varint(b)
    string_start = string_length_varnum.length
    string_end = string_start + string_length_varnum.value
    return (
        b[string_start : string_end].decode("utf-8"),
        b[string_end :]
    )


def read_compressed_packet(b: bytes, protocol_number: int) -> tuple[bytes, bool]:
    init_b = b
    try:
        packet_length_varnum = read_varint(b)
    except IndexError:
        return (init_b, False)
    b = b[packet_length_varnum.length :]

    uncompressed_length_varnum = read_varint(b)
    b = b[uncompressed_length_varnum.length :]
    decomp = zlib.decompress(b) if uncompressed_length_varnum.value != 0 else b

    if b[0] == protocol_number:
        return (b[1:], True)
    else:
        return (init_b, False)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SetCompression:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
    threshold: int

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        b, ok = read_basic_packet(b, 0x3)
        if not ok:
            return (None, b)

        threshold_varnum = read_varint(b)
        b = b[threshold_varnum.length :]

        return (cls(threshold=threshold_varnum.value), b)

@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class Disconnect:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Disconnect_(login)
    reason: str

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        b, ok = read_basic_packet(b, 0x0)
        if not ok:
            return (None, b)
        
        reason, b = read_string(b)
        return (cls(reason=reason), b)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class LoginSuccess:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success
    # game_profile: GameProfile

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        b, ok = read_compressed_packet(b, 0x2)
        if not ok:
            return (None, b)

        # TODO: Parse game_profile, if you _really_ want. I don't think it's necessary.

        # TODO: Return the actual continuation (after parsing `game_profile`).
        return (cls(), b)
