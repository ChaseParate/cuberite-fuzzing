from boofuzz import Fuzzable, String

from fuzzing.models.varint_blocks import VarIntSized
from fuzzing.protocol.packets.serverbound import create_compressed_packet


def chat_packet(compression_threshold: int = 0, max_len: int | None = None) -> Fuzzable:
    return create_compressed_packet(
        "Chat",
        0x2,
        VarIntSized(
            "Length",
            children=[String("Chat Message", "Hello, World!", max_len=max_len)],
        ),
        compression_threshold,
    )
