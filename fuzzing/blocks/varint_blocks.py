from typing import Iterable, override

import boofuzz

from fuzzing.models.varint import VarInt, VarLong


class VarIntBlock(boofuzz.BitField):
    """32 bit VarInt primitive.
    :param name: Name, for referencing later
    :param default_value: Default integer value, defaults to 0
    :param max_num: Maximum number to iterate to, defaults to the maximum 32-bit integer
    :param fuzz_values: Interesting values to fuzz, defaults to none
    :param full_range: If enabled the field mutates through *all* possible values
    :param fuzzable: Enable/Disable fuzzing for this primitive
    """

    @override
    def __init__(
        self,
        name: str | None = None,
        default_value: int = 0,
        max_num: int = 2**31 - 1,
        fuzz_values: list[int] | None = None,
        full_range: bool = False,
        fuzzable: bool = False,
        **kwargs,
    ):
        super().__init__(
            name=name,
            default_value=default_value,
            max_num=max_num,
            fuzz_values=fuzz_values,
            full_range=full_range,
            fuzzable=fuzzable,
            signed=True,
            width=32,
            **kwargs,
        )

    @override
    def encode(self, value: int, mutation_context) -> bytes:
        return VarInt(value).write()


class VarLongBlock(boofuzz.BitField):
    """64 bit VarLong primitive.
    :param name: Name, for referencing later
    :param default_value: Default integer value, defaults to 0
    :param max_num: Maximum number to iterate to, defaults to the maximum 64-bit integer
    :param fuzz_values: Interesting values to fuzz, defaults to none
    :param full_range: If enabled the field mutates through *all* possible values
    :param fuzzable: Enable/Disable fuzzing for this primitive
    """

    @override
    def __init__(
        self,
        name: str | None = None,
        default_value: int = 0,
        max_num: int = 2**63 - 1,
        fuzz_values: list[int] | None = None,
        full_range: bool = False,
        fuzzable: bool = False,
        **kwargs,
    ):
        super().__init__(
            name=name,
            default_value=default_value,
            max_num=max_num,
            fuzz_values=fuzz_values,
            full_range=full_range,
            fuzzable=fuzzable,
            signed=True,
            width=64,
            **kwargs,
        )

    @override
    def encode(self, value: int, mutation_context) -> bytes:
        return VarLong(value).write()


class VarIntSized(boofuzz.FuzzableBlock):
    """Block of data prefixed by a VarInt size
    :param name: Name, for referencing later
    :param request: Request this block belongs to
    :param children: Children of this block
    :param item_size: Size of each item in bytes, defaults to 1
    """

    item_size: int

    @override
    def __init__(
        self,
        name: str | None = None,
        request: boofuzz.Request | None = None,
        children: Iterable[boofuzz.Fuzzable] | None = None,
        item_size: int = 1,
        **kwargs,
    ):
        super().__init__(
            name=name,
            request=request,
            children=children,
            fuzzable=children is not None and any(child.fuzzable for child in children),
            **kwargs,
        )
        self.item_size = item_size

    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        size: bytes = VarInt(len(data) // self.item_size).write()
        return size + data


class VarLongSized(boofuzz.FuzzableBlock):
    """Block of data prefixed by a VarLong size
    :param name: Name, for referencing later
    :param request: Request this block belongs to
    :param children: Children of this block
    :param item_size: Size of each item in bytes, defaults to 1
    """

    item_size: int

    @override
    def __init__(
        self,
        name: str | None = None,
        request: boofuzz.Request | None = None,
        children: Iterable[boofuzz.Fuzzable] | None = None,
        item_size: int = 1,
        **kwargs,
    ):
        super().__init__(
            name=name,
            request=request,
            children=children,
            fuzzable=children is not None and any(child.fuzzable for child in children),
            **kwargs,
        )
        self.item_size = item_size

    @override
    def encode(self, value, mutation_context) -> bytes:
        data: bytes = self.get_child_data(mutation_context=mutation_context)
        size: bytes = VarLong(len(data) // self.item_size).write()
        return size + data
