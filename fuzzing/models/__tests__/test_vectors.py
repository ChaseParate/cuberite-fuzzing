import pytest

from fuzzing.models.vectors import LpVec3, LpVec3Block, Position, PositionBlock

POS_EXAMPLES = [
    (Position(0, 0, 0), b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    (Position(-1, -1, -1), b"\xff\xff\xff\xff\xff\xff\xff\xff"),
    (
        Position(255, 255, 255),
        0b0000000000000000001111111100001111111100000000000000000011111111.to_bytes(8),
    ),
    (
        Position(18357644, 831, -20882616),
        0b0100011000000111011000110000110011111110110000010101101101001000.to_bytes(8),
    ),
]

VEC3_EXAMPLES = [
    (LpVec3(0.0, 0.0, 0.0), b"\x00"),
    (LpVec3(1.0, 0.0, -1.0), b"\xf1\xff\x00\x00\xff\xff"),
    (LpVec3(10.0, 0.2, -5.0), b"\xf6\xff\x40\x01\x05\x1f\x02"),
    (LpVec3(123457.0, 15.071, 0.0), b"\xf5\xff\x7f\xff\x00\x07\x90\xf1\x01"),
]


@pytest.mark.parametrize(("position", "packed"), POS_EXAMPLES)
def test_readwrite_position(position: Position, packed: bytes):
    block = PositionBlock("pos", position)
    encoded = block.encode(block.get_value(None), None)
    assert encoded == packed
    decoded, rest = Position.read(encoded)
    assert len(rest) == 0
    assert decoded == position


@pytest.mark.parametrize(("vec3", "packed"), VEC3_EXAMPLES)
def test_write_vec3(vec3: LpVec3, packed: bytes):
    assert vec3.write() == packed


@pytest.mark.parametrize(("vec3", "packed"), VEC3_EXAMPLES)
def test_read_vec3(vec3: LpVec3, packed: bytes):
    vec, rest = LpVec3.read(packed)
    print(vec)
    assert len(rest) == 0
    assert abs(vec.x - vec3.x) < 0.001
    assert abs(vec.y - vec3.y) < 0.001
    assert abs(vec.z - vec3.z) < 0.001


@pytest.mark.parametrize(("vec3", "packed"), VEC3_EXAMPLES)
def test_vec3_block(vec3: LpVec3, packed: bytes):
    block = LpVec3Block("vec3", vec3)
    encoded = block.encode(block.get_value(None), None)
    assert encoded == packed
