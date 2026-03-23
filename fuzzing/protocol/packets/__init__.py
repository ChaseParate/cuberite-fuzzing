from boofuzz import Fuzzable, Request

from fuzzing.models.varint_blocks import VarInt, VarIntSized


def create_packet(name: str, packet_id: int, inner: Fuzzable | None) -> Request:
    children: list[Fuzzable] = [VarInt("packet_id", packet_id)]
    if inner is not None:
        children.append(inner)

    packet = VarIntSized("length", children=children)

    return Request(name, children=packet)
