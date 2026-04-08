from boofuzz import Block, Byte, Request

from fuzzing.blocks.varint_blocks import VarIntBlock
from fuzzing.blocks.vector_blocks import PositionBlock
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState

# https://c4k3.github.io/wiki.vg/Protocol.html#Player_Digging


def create_player_digging_packet(
    state: ClientState, *, fields_fuzzable: bool = True
) -> Request:
    return create_packet(
        "Player Digging",
        0x14,
        Block(
            children=[
                VarIntBlock(
                    "Status", 0, fuzz_values=list(range(7)), fuzzable=fields_fuzzable
                ),
                PositionBlock("Location", fuzzable=fields_fuzzable),
                Byte("Face", fuzz_values=list(range(6)), fuzzable=fields_fuzzable),
            ]
        ),
    )
