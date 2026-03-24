from boofuzz import Block, Fuzzable, Request

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol.encoders import compressed


def create_packet(name: str, packet_id: int, inner: Fuzzable | None) -> Request:
    children: list[Fuzzable] = [VarInt("packet_id", packet_id)]
    if inner is not None:
        children.append(inner)

    packet = VarIntSized("length", children=children)

    return Request(name, children=packet)


def create_compressed_packet(
    name: str, packet_id: int, inner: Fuzzable | None, threshold: int = 0
) -> Request:
    children: list[Fuzzable] = [VarInt("packet_id", packet_id)]
    if inner is not None:
        children.append(inner)

    packet = VarIntSized(
        "length",
        children=[
            Block("compressed", children=children, encoder=compressed(threshold))
        ],
    )

    return Request(name, children=packet)