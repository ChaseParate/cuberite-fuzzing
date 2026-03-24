import zlib
from typing import Callable

from fuzzing.models.varint import VarInt


def compressed(threshold: int = 0) -> Callable[[bytes], bytes]:
    def compress(data: bytes) -> bytes:
        if len(data) < threshold:
            return VarInt(0).write() + data
        else:
            return VarInt(len(data)).write() + zlib.compress(data)

    return compress
