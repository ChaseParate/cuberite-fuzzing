import logging

import boofuzz

from fuzzing.models.prefixed_blocks import IDOrX, PrefixedOptional
from fuzzing.models.varint_blocks import VarInt


def test_optional_empty():
    block = PrefixedOptional("foo", child=None)
    assert block.num_mutations(None) == 1
    for mutation in block.get_mutations():
        assert mutation is None
    result = block.encode(block.get_value(None), None)
    assert result == b"\x00"


def test_optional_full():
    child = boofuzz.DWord("foo", default_value=42, endian=">")
    block = PrefixedOptional("bar", child=child)
    assert block.num_mutations(None) == child.num_mutations(42)
    result = block.encode(block.get_value(None), None)
    assert result == b"\x01\x00\x00\x00\x2a"


def test_optional_mutations():
    dword = boofuzz.DWord("foo", default_value=42, endian=">")
    block = PrefixedOptional(
        "bar", child=boofuzz.DWord("foo", default_value=42, endian=">")
    )
    for word_mutation, block_mutation in zip(
        dword.mutations(42), block.mutations(None)
    ):
        assert block.encode(block_mutation, None) == b"\x01" + dword.encode(
            word_mutation, None
        )


def test_id_or_x_id():
    block = IDOrX("foo", child=5)
    result = block.encode(block.get_value(None), None)
    assert result == b"\x05"


def test_id_or_x_x():
    block = IDOrX("foo", child=boofuzz.DWord("foo", default_value=42, endian=">"))
    result = block.encode(block.get_value(None), None)
    assert result == b"\x00\x00\x00\x00\x2a"


def test_id_or_x_id_mutations():
    num = VarInt("foo", 42)
    block = IDOrX("bar", child=42)
    assert block.num_mutations(None) == num.num_mutations(42)


def test_id_or_x_x_mutations():
    dword = boofuzz.DWord("foo", default_value=42, endian=">")
    block = IDOrX("bar", child=boofuzz.DWord("foo", default_value=42, endian=">"))
    for word_mutation, block_mutation in zip(
        dword.mutations(42), block.mutations(None)
    ):
        assert block.encode(block_mutation, None) == b"\x00" + dword.encode(
            word_mutation, None
        )
