from typing import Callable
from fuzzing.models.varint import write_varint
import zlib

def compressed(threshold: int = 0) -> Callable[[bytes], bytes]:
    def compress(data: bytes) -> bytes:
        if len(data) < threshold:
            return write_varint(0) + data
        else:
            return write_varint(len(data)) + zlib.compress(data)
    return compress