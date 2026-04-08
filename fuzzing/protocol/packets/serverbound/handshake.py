from boofuzz import Block, Fuzzable, Request, String, Word

from fuzzing.blocks.varint_blocks import VarIntBlock, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER
from fuzzing.protocol.packets.serverbound import create_packet

# https://c4k3.github.io/wiki.vg/Protocol.html#Handshake


def create_handshake_packet(
    subname: str, intent_field: Fuzzable, server_address_and_port_fuzzable=False
) -> Request:
    return create_packet(
        f"Handshake ({subname})",
        0x0,
        Block(
            children=(
                VarIntBlock("Protocol Version", PROTOCOL_VERSION_NUMBER),
                VarIntSized(
                    "Server Address",
                    children=(
                        String(
                            max_len=255,
                            fuzzable=server_address_and_port_fuzzable,
                        ),
                    ),
                ),
                Word(
                    "Server Port",
                    signed=False,
                    fuzzable=server_address_and_port_fuzzable,
                ),
                intent_field,
            ),
        ),
    )


HANDSHAKE_STATUS = create_handshake_packet("Status", VarIntBlock("intent", 1))
HANDSHAKE_LOGIN = create_handshake_packet("Login", VarIntBlock("intent", 2))
HANDSHAKE_ANY = create_handshake_packet(
    "Any", VarIntBlock("intent", fuzz_values=[1, 2], fuzzable=True)
)
