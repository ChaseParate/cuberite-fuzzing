from boofuzz import Block, Request, String, Word

from fuzzing.models.varint_blocks import VarInt
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake
HANDSHAKE = Request(
    "Handshake",
    children=(
        VarInt(
            "length"
        ),  # TODO: We need to make this reflect the actual packet size. Might want to look into `boofuzz.Size`.
        VarInt("packet_id", 0),
        Block(
            "handshake_data",
            children=(
                VarInt("protocol_version", PROTOCOL_VERSION_NUMBER),
                String("server_address", max_len=255),
                Word("server_port", signed=False),
                VarInt("intent", 1),  # TODO: Replace this with a `boofuzz.Group`?
            ),
        ),
    ),
)
