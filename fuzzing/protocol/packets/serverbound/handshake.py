from boofuzz import Block, Fuzzable, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER
from fuzzing.protocol.packets.serverbound import create_packet

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake


def create_handshake_packet(
    subname: str, intent_field: Fuzzable, server_address_and_port_fuzzable=False
) -> Request:
    return create_packet(
        f"Handshake ({subname})",
        0,
        Block(
            "handshake_data",
            children=(
                # TODO: Should we experiment with fuzzing this?
                VarInt("protocol_version", PROTOCOL_VERSION_NUMBER),
                VarIntSized(
                    "server_address",
                    children=(
                        String(
                            "server_address_raw",
                            max_len=255,
                            fuzzable=server_address_and_port_fuzzable,
                        ),
                    ),
                ),
                Word(
                    "server_port",
                    signed=False,
                    fuzzable=server_address_and_port_fuzzable,
                ),
                intent_field,
            ),
        ),
    )


HANDSHAKE_STATUS = create_handshake_packet("Status", VarInt("intent", 1))
HANDSHAKE_LOGIN = create_handshake_packet("Login", VarInt("intent", 2))
HANDSHAKE_ANY = create_handshake_packet(
    "Any", VarInt("intent", fuzz_values=[1, 2, 3], fuzzable=True)
)
