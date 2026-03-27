from boofuzz import Request

from fuzzing.models.varint_blocks import VarIntBlock
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_teleport_confirm_packet(state: ClientState) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Teleport_Confirm

    return create_packet(
        "Teleport Confirm",
        0x0,
        # This value will be hot-swapped with the correct value at runtime.
        VarIntBlock("Teleport ID", fuzzable=False),
        state.compression_threshold,
    )
