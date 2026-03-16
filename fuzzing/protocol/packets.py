from boofuzz import Block, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER


def create_packet(name: str, packet_id: int, block: Block) -> Request:
    return Request(
        name,
        children=(
            VarIntSized("length", children=(VarInt("packet_id", packet_id), block))
        ),
    )


# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake
HANDSHAKE = create_packet(
    "Handshake",
    0,
    Block(
        "handshake_data",
        children=(
            # TODO: Should we experiment with fuzzing this?
            VarInt("protocol_version", PROTOCOL_VERSION_NUMBER),
            VarIntSized(
                "server_address",
                children=(
                    # TODO: We should consider disabling fuzzing for this and the port.
                    #       Those fields are unused according to the spec and will likely just cause us to waste a bunch of time.
                    String("server_address_raw", max_len=255),
                ),
            ),
            Word("server_port", signed=False, fuzzable=True),
            # TODO: Replace this with a `boofuzz.Group`?
            VarInt("intent", 1),
        ),
    ),
)
