import zlib

from boofuzz import Block, Fuzzable, Request

from fuzzing.models.varint_blocks import VarInt, VarIntBlock, VarIntSized
from fuzzing.protocol.encoders import compressed


def create_packet(
    name: str, packet_id: int, inner: Fuzzable | None, threshold: int | None = None
) -> Request:
    children: list[Fuzzable] = [VarIntBlock("packet_id", packet_id)]
    if inner is not None:
        children.append(inner)

    packet = VarIntSized(
        "length",
        children=children
        if threshold is None
        else [Block("compressed", children=children, encoder=compressed(threshold))],
    )

    return Request(name, children=packet)


def create_raw_packet(
    packet_id: int, inner: bytes | None, threshold: int | None = None
) -> bytes:
    contents: bytes = VarInt(packet_id).write()
    if inner is not None:
        contents += inner

    if threshold is not None:
        if len(contents) >= threshold:
            contents = VarInt(len(contents)).write() + zlib.compress(contents)
        else:
            contents = VarInt(0).write() + contents

    return VarInt(len(contents)).write() + contents
