import pytest

from fuzzing.__tests__.vector_example_data import LPVEC3_EXAMPLES, POSITION_EXAMPLES
from fuzzing.blocks.vector_blocks import LpVec3Block, PositionBlock
from fuzzing.models.vectors import LpVec3, Position


@pytest.mark.parametrize(("position", "packed"), POSITION_EXAMPLES)
def test_position_block(position: Position, packed: bytes):
    block = PositionBlock("pos", position)
    encoded = block.encode(block.get_value(None), None)
    assert encoded == packed


@pytest.mark.parametrize(("vec3", "packed"), LPVEC3_EXAMPLES)
def test_vec3_block(vec3: LpVec3, packed: bytes):
    block = LpVec3Block("vec3", vec3)
    encoded = block.encode(block.get_value(None), None)
    assert encoded == packed
