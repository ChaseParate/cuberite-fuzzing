import dataclasses
import struct
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


def _get_integer_size_format(size: int) -> str:
    match size:
        case 1:
            return "b"
        case 2:
            return "h"
        case 4:
            return "i"
        case 8:
            return "d"
        case _:
            raise ValueError("Invalid integer size")


def read_integer(raw: bytes, size: int, signed: bool) -> tuple[int, bytes]:
    size_format = _get_integer_size_format(size)
    size_format = size_format.upper() if signed else size_format.lower()

    int_bytes, rest = raw[:size], raw[size:]
    return (struct.unpack(f"<{size_format}", int_bytes)[0], rest)


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
    # https://c4k3.github.io/wiki.vg/Protocol.html#Login_Success

    uuid: str
    username: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x2)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        uuid, packet = read_string(raw)
        username, packet = read_string(packet)

        return cls(uuid=uuid, username=username)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class JoinGame:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Join_Game

    entity_id: int
    gamemode: int
    dimension: int
    difficulty: int
    max_players: int
    level_type: str
    reduced_debug_info: bool

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x23)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        entity_id, raw = read_integer(raw, 4, True)
        gamemode, raw = read_integer(raw, 1, False)
        dimension, raw = read_integer(raw, 4, True)
        difficulty, raw = read_integer(raw, 1, False)
        max_players, raw = read_integer(raw, 1, False)
        level_type, raw = read_string(raw)
        reduced_debug_info, raw = read_integer(raw, 1, False)

        return cls(
            entity_id=entity_id,
            gamemode=gamemode,
            dimension=dimension,
            difficulty=difficulty,
            max_players=max_players,
            level_type=level_type,
            reduced_debug_info=bool(reduced_debug_info),
        )
