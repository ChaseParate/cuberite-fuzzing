import pytest
from fuzzing.models.varint import read_varint, write_varint, read_varlong, write_varlong

VARINT_EXAMPLES = [
    (0, b"\x00"),
    (1, b"\x01"),
    (2, b"\x02"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (255, b"\xff\x01"),
    (25565, b"\xdd\xc7\x01"),
    (2097151, b"\xff\xff\x7f"),
    (2147483647, b"\xff\xff\xff\xff\x07"),
    (-1, b"\xff\xff\xff\xff\x0f"),
    (-2147483648, b"\x80\x80\x80\x80\x08"),
]

VARLONG_EXAMPLES = [
    (0, b"\x00"),
    (1, b"\x01"),
    (2, b"\x02"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (255, b"\xff\x01"),
    (2147483647, b"\xff\xff\xff\xff\x07"),
    (9223372036854775807, b"\xff\xff\xff\xff\xff\xff\xff\xff\x7f"),
    (-1, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
    (-2147483648, b"\x80\x80\x80\x80\xf8\xff\xff\xff\xff\x01"),
    (-9223372036854775808, b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"),
]


@pytest.mark.parametrize(("number", "varint"), VARINT_EXAMPLES)
def test_read_varint(number: int, varint: bytes):
    assert read_varint(varint) == number


@pytest.mark.parametrize(("number", "varint"), VARINT_EXAMPLES)
def test_write_varint(number: int, varint: bytes):
    assert write_varint(number) == varint


@pytest.mark.parametrize(("number", "varlong"), VARLONG_EXAMPLES)
def test_read_varlong(number: int, varlong: bytes):
    assert read_varlong(varlong) == number


@pytest.mark.parametrize(("number", "varlong"), VARLONG_EXAMPLES)
def test_write_varlong(number: int, varlong: bytes):
    assert write_varlong(number) == varlong


def test_read_varint_toolarge():
    with pytest.raises(RuntimeError):
        read_varint(b"\xff\xff\xff\xff\xff\xff")


def test_read_varlong_toolarge():
    with pytest.raises(RuntimeError):
        read_varlong(b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01")
