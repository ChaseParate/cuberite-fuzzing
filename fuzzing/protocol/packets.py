from boofuzz import Block, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake
HANDSHAKE = Request(
    "Handshake",
    children=(
        VarIntSized(
            "length",
            children=(
                VarInt("packet_id", 0),
                Block(
                    "handshake_data",
                    children=(
                        VarInt("protocol_version", PROTOCOL_VERSION_NUMBER),
                        String("server_address", max_len=255),
                        Word("server_port", signed=False),
                        # TODO: Replace this with a `boofuzz.Group`?
                        VarInt("intent", 1),
                    ),
                ),
            ),
        )
    ),
)
