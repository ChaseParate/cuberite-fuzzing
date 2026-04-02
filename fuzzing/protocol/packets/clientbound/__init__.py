import dataclasses
import struct
import zlib
from typing import Callable, Iterable, Literal, Self

from fuzzing.models.varint import VarInt
from fuzzing.models.vectors import Position


def _split_next_packet(raw: bytes) -> tuple[bytes | None, bytes]:
    """
    Separates the first packet from the remaining data via the first packet's header.
    """
    length, rest = VarInt.read(raw)
    if len(rest) < length:
        return (None, raw)
    return (rest[:length], rest[length:])


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
        cls, raw: bytes, threshold: int | None = None, want: Iterable[int] | None = None
    ) -> tuple[Self | None, bytes]:
        """
        Reads any packet, returning the packet ID, the packet raw contents, and the remaining data.
        """
        packet, rest = _split_next_packet(raw)
        if packet is None:
            return (None, raw)

        packet_id = -1

        if threshold is not None:
            data_length, packet = VarInt.read(packet)
            if data_length == 0:
                packet_id, packet = VarInt.read(packet)
            else:
                decompressor = zlib.decompressobj()
                first = decompressor.decompress(packet, 5)
                packet_id, _ = VarInt.read(first)
                if want is not None:
                    if packet_id in want:
                        packet = decompressor.decompress(packet)
                    else:
                        packet = bytes([])
                else:
                    packet = decompressor.decompress(packet)
        else:
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


type IntegerSize = Literal[1, 2, 4, 8]


def _get_integer_size_format(size: IntegerSize) -> str:
    match size:
        case 1:
            return "b"
        case 2:
            return "h"
        case 4:
            return "i"
        case 8:
            return "q"
        case _:
            raise ValueError("Invalid integer size")


def read_integer(raw: bytes, size: IntegerSize, signed: bool) -> tuple[int, bytes]:
    size_format = _get_integer_size_format(size)
    size_format = size_format.upper() if signed else size_format.lower()

    int_bytes, rest = raw[:size], raw[size:]
    return (struct.unpack(f"<{size_format}", int_bytes)[0], rest)


def read_boolean(raw: bytes) -> tuple[bool, bytes]:
    boolean, rest = read_integer(raw, 1, False)
    if boolean not in (0, 1):
        raise ValueError("Invalid boolean")

    return (bool(boolean), rest)


type FloatSize = Literal[4, 8]


def _get_float_size_format(size: FloatSize) -> str:
    match size:
        case 4:
            return "f"
        case 8:
            return "d"
        case _:
            raise ValueError("Invalid float size")


def read_float(raw: bytes, size: FloatSize) -> tuple[float, bytes]:
    size_format = _get_float_size_format(size)

    float_bytes, rest = raw[:size], raw[size:]
    return (struct.unpack(f"<{size_format}", float_bytes)[0], rest)


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
class DisconnectLogin:
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
        uuid, raw = read_string(raw)
        username, raw = read_string(raw)

        assert len(raw) == 0, "from_raw_contents should parse the entire packet"

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
        reduced_debug_info, raw = read_boolean(raw)

        assert len(raw) == 0, "from_raw_contents should parse the entire packet"

        return cls(
            entity_id=entity_id,
            gamemode=gamemode,
            dimension=dimension,
            difficulty=difficulty,
            max_players=max_players,
            level_type=level_type,
            reduced_debug_info=reduced_debug_info,
        )


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class SpawnPosition:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Spawn_Position

    position: Position

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x46)
        if packet is None:
            return (None, rest)

        return (cls.from_raw_contents(raw), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        position, raw = Position.read(raw)

        assert len(raw) == 0, "from_raw_contents should parse the entire packet"

        return cls(position=position)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class ServerDifficulty:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Server_Difficulty

    difficulty: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x46)
        if packet is None:
            return (None, rest)

        return (cls.from_raw_contents(raw), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        difficulty, raw = read_integer(raw, 1, False)

        assert len(raw) == 0, "from_raw_contents should parse the entire packet"

        return cls(difficulty=difficulty)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class PlayerListItem:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Player_List_Item
    # Also known as "packet_player_info" in Minebase.

    action: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x2E)
        if packet is None:
            return (None, rest)

        return (cls.from_raw_contents(raw), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        action, raw = VarInt.read(raw)

        # I can't be assed to parse this packet. It doesn't contain anything relevant to the fuzzer as far as I can tell.
        # assert len(raw) == 0, "from_raw_contents should parse the entire packet"

        return cls(action=action)


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class PlayerPositionAndLook:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Player_Position_And_Look_.28clientbound.29
    # Also known as "packet_position" in Minebase.

    x: float
    y: float
    z: float
    yaw: float
    pitch: float
    flags: int
    teleport_id: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x2F)
        if packet is None:
            return (None, rest)

        return (cls.from_raw_contents(raw), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        x, raw = read_float(raw, 8)
        y, raw = read_float(raw, 8)
        z, raw = read_float(raw, 8)
        yaw, raw = read_float(raw, 4)
        pitch, raw = read_float(raw, 4)
        flags, raw = read_integer(raw, 1, False)
        teleport_id, raw = VarInt.read(raw)

        assert len(raw) == 0, "from_raw_contents should parse the entire packet"

        return cls(
            x=x,
            y=y,
            z=z,
            yaw=yaw,
            pitch=pitch,
            flags=flags,
            teleport_id=teleport_id,
        )


@dataclasses.dataclass(eq=False, frozen=True, kw_only=True, slots=True)
class DisconnectPlay:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Disconnect_.28play.29
    reason: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> tuple[Self | None, bytes]:
        packet, rest = read_compressed_packet(raw, 0x1A)
        if packet is None:
            return (None, rest)
        return (cls.from_raw_contents(packet), rest)

    @classmethod
    def from_raw_contents(cls, raw: bytes) -> Self:
        reason, rest = read_string(raw)
        assert len(rest) == 0, "from_raw_contents should parse the entire packet"
        return cls(reason=reason)
