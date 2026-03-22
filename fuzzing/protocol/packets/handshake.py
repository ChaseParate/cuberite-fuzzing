from boofuzz import Block, Fuzzable, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER
from fuzzing.protocol.packets import create_packet

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake


def create_handshake_packet(intent_field: Fuzzable) -> Request:
    return create_packet(
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
                intent_field,
            ),
        ),
    )


HANDSHAKE_STATUS = create_handshake_packet(VarInt("intent", 1))
HANDSHAKE_LOGIN = create_handshake_packet(VarInt("intent", 2))
HANDSHAKE_ANY = create_handshake_packet(
    VarInt("intent", fuzz_values=[1, 2, 3], fuzzable=True)
)
