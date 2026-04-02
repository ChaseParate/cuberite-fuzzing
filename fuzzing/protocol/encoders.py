import zlib
from typing import Callable

from fuzzing.models.varint import VarInt
from fuzzing.protocol.state import ClientState


def compressed(state: ClientState) -> Callable[[bytes], bytes]:
    def compress(data: bytes) -> bytes:
        if state.compression_threshold is not None:
            if len(data) < state.compression_threshold:
                return VarInt(0).write() + data
            else:
                return VarInt(len(data)).write() + zlib.compress(data)
        return data

    return compress
