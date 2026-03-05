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


def test_varint_sized_array():
    arr = VarIntSized(
        "foo",
        children=(boofuzz.String("bar", "bar", 3), boofuzz.String("baz", "baz", 3)),
        item_size=3,
    )
    result = arr.encode(arr.get_value(None), None)
    assert result == b"\x02barbaz"


def test_varint_sized_array_huge():
    huge_arr = [boofuzz.Word(f"word{i}", 4, endian=">") for i in range(1024)]
    arr = VarIntSized("foo", children=tuple(huge_arr), item_size=2)
    result = arr.encode(arr.get_value(None), None)
    assert result == varint.write_varint(1024) + b"\x00\x04" * 1024


def test_varlong_sized_array():
    arr = VarLongSized(
        "foo",
        children=(boofuzz.String("bar", "bar", 3), boofuzz.String("baz", "baz", 3)),
        item_size=3,
    )
    result = arr.encode(arr.get_value(None), None)
    assert result == b"\x02barbaz"


def test_varlong_sized_array_huge():
    huge_arr = [boofuzz.Word(f"word{i}", 4, endian=">") for i in range(1024)]
    arr = VarLongSized("foo", children=tuple(huge_arr), item_size=2)
    result = arr.encode(arr.get_value(None), None)
    assert result == varint.write_varlong(1024) + b"\x00\x04" * 1024
