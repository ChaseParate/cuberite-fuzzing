from boofuzz import Block, Byte, Bytes, Request, String

from fuzzing.models.varint_blocks import VarIntSized
from fuzzing.models.vectors import Position, PositionBlock
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def tab_complete_packet(
    state: ClientState,
    is_command: bool = False,
    looking_at: Position | PositionBlock | None = None,
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Tab-Complete_.28serverbound.29

    if looking_at is None:
        position_segment = [Byte("Has Position", 0, fuzzable=False)]
    elif isinstance(looking_at, Position):
        position_segment = [
            Byte("Has Position", 1, fuzzable=False),
            PositionBlock("Looking At", looking_at, fuzzable=False),
        ]
    else:
        position_segment = [Byte("Has Position", 1, fuzzable=False), looking_at]
    return create_packet(
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
        state,
    )


def plugin_message_packet(
    state: ClientState,
    max_length: int | None = None,
    max_channel_length: int | None = None,
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29

    return create_packet(
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
        state,
    )
