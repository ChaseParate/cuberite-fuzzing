import dataclasses
import zlib
from typing import Self

from fuzzing.models.varint import VarInt


def read_basic_packet_header(b: bytes, protocol_number: int) -> bytes | None:
    try:
        b, length = VarInt.read(b)
    except IndexError:
        return None

    if b[0] == protocol_number:
        return b[1:]
    else:
        return None


def read_string(b: bytes) -> tuple[str, bytes]:
    b, length = VarInt.read(b)
    string = b[:length]
    return (string.decode("utf-8"), b[length:])


def read_compressed_packet(b: bytes, protocol_number: int) -> bytes | None:
    try:
        b, packet_length = VarInt.read(b)
    except IndexError:
        return None

    b, uncompressed_length = VarInt.read(b)
    decomp = zlib.decompress(b) if uncompressed_length != 0 else b

    if decomp[0] == protocol_number:
        return decomp[1:]
    else:
        return None


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SetCompression:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
    threshold: int

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        pack = read_basic_packet_header(b, 0x3)
        if not pack:
            return (None, b)

        pack, threshold = VarInt.read(pack)

        return (cls(threshold=threshold), pack)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class Disconnect:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Disconnect_(login)
    reason: str

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        pack = read_basic_packet_header(b, 0x0)
        if not pack:
            return (None, b)

        reason, pack = read_string(pack)
        return (cls(reason=reason), pack)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class LoginSuccess:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success
    # game_profile: GameProfile

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        pack = read_compressed_packet(b, 0x2)
        if not pack:
            return (None, b)

        # TODO: Parse game_profile, if you _really_ want. I don't think it's necessary.

        # TODO: Return the actual continuation (after parsing `game_profile`).
        return (cls(), pack)
