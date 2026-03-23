from boofuzz import Block, Fuzzable, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER


def create_packet(name: str, packet_id: int, block: Block | None) -> Request:
    children: list[Fuzzable] = [VarInt("packet_id", packet_id)]
    if block is not None:
        children.append(block)

    packet = VarIntSized("length", children=children)

    return Request(name, children=packet)
