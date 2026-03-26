import dataclasses
import zlib
from typing import Callable, Self

from fuzzing.models.varint import VarInt


def _split_next_packet(raw: bytes) -> tuple[bytes | None, bytes]:
    """
    Separates the first packet from the remaining data via the first packet's header.
    """
    try:
        length, rest = VarInt.read(raw)
        return (rest[:length], rest[length:])
    except IndexError:
        return (None, raw)


def _read_packet(
    raw: bytes,
    expected_packet_id: int,
    *,
    decompress_packet_fn: Callable[[bytes], bytes] | None = None,
) -> tuple[bytes | None, bytes]:
    """
    Reads a packet, returning the packet data and any extra bytes if successful, or None and the original bytes if unsuccessful.
    """
    packet, rest = _split_next_packet(raw)
    if packet is None:
        return (None, raw)

    if decompress_packet_fn is not None:
        packet = decompress_packet_fn(packet)

    id, packet = VarInt.read(packet)
    return (packet, rest) if id == expected_packet_id else (None, raw)


@dataclasses.dataclass(frozen=True, slots=True)
class RawPacket:
    id: int
    contents: bytes

    @classmethod
    def read(
        cls, raw: bytes, threshold: int | None = None
    ) -> tuple[Self | None, bytes]:
        """
        Reads any packet, returning the packet ID, the packet raw contents, and the remaining data.
        """
        packet, rest = _split_next_packet(raw)
        if packet is None:
            return (None, raw)

        if threshold is not None:
            data_length, packet = VarInt.read(packet)
            packet = zlib.decompress(packet) if data_length > 0 else packet

        packet_id, packet = VarInt.read(packet)
        return (cls(packet_id, packet), rest)


def read_uncompressed_packet(
    raw: bytes, expected_packet_id: int
) -> tuple[bytes | None, bytes]:
    return _read_packet(raw, expected_packet_id)


def read_compressed_packet(
    raw: bytes, expected_packet_id: int
) -> tuple[bytes | None, bytes]:
    def decompress_packet(packet: bytes) -> bytes:
        data_length, packet = VarInt.read(packet)
        return zlib.decompress(packet) if data_length > 0 else packet

    return _read_packet(raw, expected_packet_id, decompress_packet_fn=decompress_packet)


def read_string(raw: bytes) -> tuple[str, bytes]:
    length, raw = VarInt.read(raw)
    return (raw[:length].decode("utf-8"), raw[length:])


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SetCompression:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Set_Compression
    threshold: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_uncompressed_packet(raw, 0x3)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        threshold, rest = VarInt.read(raw)
        assert len(rest) == 0, "from_raw_contents should parse the entire packet"
        return cls(threshold=threshold)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class Disconnect:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Disconnect_(login)
    reason: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_uncompressed_packet(raw, 0x0)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        reason, rest = read_string(raw)
        assert len(rest) == 0, "from_raw_contents should parse the entire packet"
        return cls(reason=reason)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class LoginSuccess:
    # https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Success

    # game_profile: GameProfile

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x2)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        # TODO: Parse game_profile, if you _really_ want. I don't think it's necessary.
        return cls()
