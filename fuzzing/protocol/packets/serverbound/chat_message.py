from boofuzz import Request, String

from fuzzing.models.varint_blocks import VarIntSized
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_chat_message_packet(
    state: ClientState, *, fields_fuzzable: bool = True, enforce_max_length: bool = True
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Chat_Message_.28serverbound.29

    return create_packet(
        "Chat Message",
        0x2,
        VarIntSized(
            "Message",
            children=(
                String(
                    max_len=256 if enforce_max_length else None,
                    fuzzable=fields_fuzzable,
                ),
            ),
        ),
        state.compression_threshold,
    )
