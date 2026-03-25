from boofuzz import Block, Byte, Bytes, Fuzzable, String

from fuzzing.models.varint_blocks import VarIntSized
from fuzzing.models.vectors import Position, PositionBlock
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


def tab_complete_packet(
    compression_threshold: int = 0,
    is_command: bool = False,
    looking_at: Position | PositionBlock | None = None,
) -> Fuzzable:
    if looking_at is None:
        position_segment = [Byte("Has Position", 0, fuzzable=False)]
    elif isinstance(looking_at, Position):
        position_segment = [
            Byte("Has Position", 1, fuzzable=False),
            PositionBlock("Looking At", looking_at, fuzzable=False),
        ]
    else:
        position_segment = [Byte("Has Position", 1, fuzzable=False), looking_at]
    return create_compressed_packet(
        "Tab Complete",
        0x1,
        Block(
            "Contents",
            children=[
                VarIntSized("Length", children=[String("Text", "/he")]),
                Byte("Assume Command", 1 if is_command else 0, fuzzable=False),
                *position_segment,
            ],
        ),
        compression_threshold,
    )


def plugin_message_packet(
    compression_threshold: int = 0,
    max_length: int | None = None,
    max_channel_length: int | None = None,
) -> Fuzzable:
    return create_compressed_packet(
        "Plugin Message",
        0x9,
        Block(
            "Contents",
            children=[
                VarIntSized(
                    "Length", children=[String("Channel", max_len=max_channel_length)]
                ),
                Bytes("Data")
                if max_length is None
                else Bytes("Data", max_len=max_length),
            ],
        ),
        compression_threshold,
    )
