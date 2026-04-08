from fuzzing.models.vectors import LpVec3, Position

POSITION_EXAMPLES = [
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

LPVEC3_EXAMPLES = [
    (LpVec3(0.0, 0.0, 0.0), b"\x00"),
    (LpVec3(1.0, 0.0, -1.0), b"\xf1\xff\x00\x00\xff\xff"),
    (LpVec3(10.0, 0.2, -5.0), b"\xf6\xff\x40\x01\x05\x1f\x02"),
    (LpVec3(123457.0, 15.071, 0.0), b"\xf5\xff\x7f\xff\x00\x07\x90\xf1\x01"),
]
