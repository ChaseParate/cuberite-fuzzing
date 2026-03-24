import pytest

from fuzzing.models.vectors import Position, PositionBlock, LpVec3

POS_EXAMPLES = [
    (Position(0, 0, 0),                  b'\x00\x00\x00\x00\x00\x00\x00\x00'),
    (Position(-1, -1, -1),               b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'),
    (Position(255, 255, 255),            int('0' * 18 + '1' * 8 + '0' * 18 + '1' * 8 + '0' * 4 + '1' * 8, 2).to_bytes(8)),
    (Position(18357644, 831, -20882616), int('0100011000000111011000110010110000010101101101001000001100111111', 2).to_bytes(8)),
]

VEC3_EXAMPLES = [
    (LpVec3(0.0, 0.0, 0.0),         b'\x00'),
    (LpVec3(1.0, 0.0, -1.0),        b'\xF1\xFF\x00\x00\xFF\xFF'),
    (LpVec3(10.0, 0.2, -5.0),       b'\xF6\xFF\x40\x01\x05\x1F\x02'),
    (LpVec3(123457.0, 15.071, 0.0), b'\xF5\xFF\x7F\xFF\x00\x07\x90\xF1\x01')
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