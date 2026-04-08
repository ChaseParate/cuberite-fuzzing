import pytest

from fuzzing.__tests__.vector_example_data import LPVEC3_EXAMPLES, POSITION_EXAMPLES
from fuzzing.models.vectors import LpVec3, Position


@pytest.mark.parametrize(("pos", "packed"), POSITION_EXAMPLES)
def test_write_position(pos: Position, packed: bytes):
    assert pos.write() == packed


@pytest.mark.parametrize(("expected_pos", "packed"), POSITION_EXAMPLES)
def test_read_position(expected_pos: Position, packed: bytes):
    pos, rest = Position.read(packed)
    assert len(rest) == 0
    assert abs(pos.x - expected_pos.x) < 0.001
    assert abs(pos.y - expected_pos.y) < 0.001
    assert abs(pos.z - expected_pos.z) < 0.001


@pytest.mark.parametrize(("vec3", "packed"), LPVEC3_EXAMPLES)
def test_write_vec3(vec3: LpVec3, packed: bytes):
    assert vec3.write() == packed


@pytest.mark.parametrize(("expected_vec", "packed"), LPVEC3_EXAMPLES)
def test_read_vec3(expected_vec: LpVec3, packed: bytes):
    vec, rest = LpVec3.read(packed)
    assert len(rest) == 0
    assert abs(vec.x - expected_vec.x) < 0.001
    assert abs(vec.y - expected_vec.y) < 0.001
    assert abs(vec.z - expected_vec.z) < 0.001
