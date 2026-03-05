import pytest, logging, varint, boofuzz
from blocks import *

def test_varint_mutations():
    block = VarInt("foo", 0)
    for mutation in block.mutations(0):
        assert block.encode(mutation, None) == varint.write_varint(mutation)

def test_varlong_mutations():
    block = VarLong("foo", 0)
    for mutation in block.mutations(0):
        assert block.encode(mutation, None) == varint.write_varlong(mutation)
