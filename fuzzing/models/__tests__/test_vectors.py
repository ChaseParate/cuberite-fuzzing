import pytest

from fuzzing.models.vectors import Position, PositionBlock

POS_EXAMPLES = [
    (Position(0, 0, 0),       b'\x00\x00\x00\x00\x00\x00\x00\x00'),
    (Position(-1, -1, -1),    b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'),
    (Position(255, 255, 255), int('0' * 18 + '1' * 8 + '0' * 18 + '1' * 8 + '0' * 4 + '1' * 8, 2).to_bytes(8)),
    (Position(18357644, 831, -20882616), int('0100011000000111011000110010110000010101101101001000001100111111', 2).to_bytes(8)),
]

@pytest.mark.parametrize(("position", "packed"), POS_EXAMPLES)
def test_readwrite_position(position: Position, packed: bytes):
    block = PositionBlock("pos", position)
    encoded = block.encode(block.get_value(None), None)
    assert encoded == packed
    decoded, rest = Position.read(encoded)
    assert len(rest) == 0
    assert decoded == position