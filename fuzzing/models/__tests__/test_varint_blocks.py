import boofuzz
import pytest
from lorem_text import lorem

from fuzzing.models import varint
from fuzzing.models.varint_blocks import VarInt, VarIntSized, VarLong, VarLongSized


def test_varint_mutations():
    block = VarInt("foo", 0)
    for mutation in block.mutations(0):
        assert block.encode(mutation, None) == varint.write_varint(mutation)


def test_varlong_mutations():
    block = VarLong("foo", 0)
    for mutation in block.mutations(0):
        assert block.encode(mutation, None) == varint.write_varlong(mutation)


EXAMPLE_STRINGS = [
    "foo",
    "bar",
    "Pneumonoultramicroscopicsilicovolcanoconiosis",
    lorem.paragraphs(4),
]


@pytest.mark.parametrize("example", EXAMPLE_STRINGS)
def test_varint_sized(example: str):
    block = VarIntSized("foo", children=(boofuzz.String("bar", default_value=example)))
    result = block.encode(block.get_value(None), None)
    assert result == varint.write_varint(len(example)) + example.encode("utf-8")


@pytest.mark.parametrize("example", EXAMPLE_STRINGS)
def test_varlong_sized(example: str):
    block = VarLongSized("foo", children=(boofuzz.String("bar", default_value=example)))
    result = block.encode(block.get_value(None), None)
    assert result == varint.write_varlong(len(example)) + example.encode("utf-8")
