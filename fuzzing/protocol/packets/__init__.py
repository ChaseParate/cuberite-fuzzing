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
