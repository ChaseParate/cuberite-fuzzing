import dataclasses
import zlib
from typing import Callable, Self

from fuzzing.models.varint import VarInt


def _read_packet_header(packet: bytes) -> tuple[bytes, bytes]:
    length, rest = VarInt.read(packet)
    return (rest[:length], rest[length:])


def _read_packet(
    packet: bytes,
    expected_packet_id: int,
    *,
    decompress_packet_fn: Callable[[bytes], bytes] | None = None,
) -> tuple[bytes | None, bytes]:
    packet, rest = _read_packet_header(packet)

    if decompress_packet_fn is not None:
        packet = decompress_packet_fn(packet)

    id, packet = VarInt.read(packet)
    return (packet if id == expected_packet_id else None, rest)


def read_uncompressed_packet(
    packet: bytes, expected_packet_id: int
) -> tuple[bytes | None, bytes]:
    return _read_packet(packet, expected_packet_id)


def read_compressed_packet(
    packet: bytes, expected_packet_id: int
) -> tuple[bytes | None, bytes]:
    def decompress_packet(packet: bytes) -> bytes:
        data_length, packet = VarInt.read(packet)
        if data_length > 0:
            packet = zlib.decompress(packet)

        return zlib.decompress(packet) if data_length > 0 else packet

    return _read_packet(
        packet, expected_packet_id, decompress_packet_fn=decompress_packet
    )


def read_string(b: bytes) -> tuple[str, bytes]:
    length, b = VarInt.read(b)
    return (b[:length].decode("utf-8"), b[length:])


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SetCompression:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
    threshold: int

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_uncompressed_packet(b, 0x3)
        if packet is None:
            return (None, rest)

        threshold, packet_data = VarInt.read(packet)
        return (cls(threshold=threshold), rest)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class Disconnect:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Disconnect_(login)
    reason: str

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_uncompressed_packet(b, 0x0)
        if packet is None:
            return (None, rest)

        reason, packet_data = read_string(packet)
        return (cls(reason=reason), rest)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class LoginSuccess:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success

    # game_profile: GameProfile

    @classmethod
    def from_bytes(cls, b: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(b, 0x2)
        if packet is None:
            return (None, rest)

        # TODO: Parse game_profile, if you _really_ want. I don't think it's necessary.

        return (cls(), rest)
