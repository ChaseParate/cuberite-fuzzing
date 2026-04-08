from boofuzz import Request

from fuzzing.blocks.varint_blocks import VarIntBlock
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState

# https://c4k3.github.io/wiki.vg/Protocol.html#Use_Item


def create_use_item_packet(
    state: ClientState, *, fields_fuzzable: bool = True
) -> Request:
    return create_packet(
        "Use Item",
        0x20,
        VarIntBlock("Hand", 0, fuzzable=fields_fuzzable),
    )
