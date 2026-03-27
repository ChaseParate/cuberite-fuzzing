from boofuzz import Request

from fuzzing.models.varint_blocks import VarIntBlock
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_client_status_packet(
    state: ClientState, *, fields_fuzzable: bool = True
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Client_Status

    return create_packet(
        "Client Status",
        0x3,
        VarIntBlock("Action ID", fuzzable=fields_fuzzable),
        state.compression_threshold,
    )
