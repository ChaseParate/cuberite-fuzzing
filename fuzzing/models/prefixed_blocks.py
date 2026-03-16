from typing import override

import boofuzz

from fuzzing.models.varint_blocks import VarInt


class PrefixedOptional(boofuzz.Fuzzable):
    """Prefixed Optional primitive.
    :param name: Name, for referencing later
    :param child: Child block, defaults to None (the optional will be false)
    """

    child: boofuzz.Fuzzable | None

    @override
    def __init__(
        self,
        name: str | None = None,
        child: boofuzz.Fuzzable | None = None,
        *args,
        **kwargs,
    ):
        self.child = child
        super().__init__(
            name=name,
            fuzzable=child is not None and child.fuzzable,
            *args,
            **kwargs,
        )

    @override
    def mutations(self, _default_value):
        if self.child is None:
            yield None
            return
        yield from self.child.mutations(self.child.original_value())

    @override
    def get_value(self, mutation_context):
        if self.child is None:
            return None
        return self.child.get_value(mutation_context)

    @override
    def num_mutations(self, _default_value):
        if self.child is None:
            return 1
        else:
            return self.child.num_mutations(self.child.original_value())

    @override
    def encode(self, value, mutation_context) -> bytes:
        if value is None:
            return b"\x00"

        assert self.child is not None
        return b"\x01" + self.child.encode(value, mutation_context)


class IDOrX(VarInt):
    """'ID or X' type, either a reference ID or, if 0, 0 followed by an object
    :param name: Name, for referencing later
    :param child: Child block, either fuzzable or int (defaults to int 1)
    :param fuzzable: Whether to fuzz IDs, only works if child is an ID
    """

    child: boofuzz.Fuzzable | int

    @override
    def __init__(
        self,
        name: str | None = None,
        child: boofuzz.Fuzzable | int = 1,
        fuzzable: bool = False,
        *args,
        **kwargs,
    ):
        self.child = child
        super().__init__(
            name, child if isinstance(child, int) else 0, fuzzable, *args, **kwargs
        )

    @override
    def mutations(self, default_value):
        if isinstance(self.child, int):
            yield from super().mutations(self.child)
        else:
            yield from self.child.mutations(self.child.original_value())

    @override
    def num_mutations(self, default_value):
        if isinstance(self.child, int):
            return super().num_mutations(self.child)
        else:
            return self.child.num_mutations(self.child.original_value())

    @override
    def get_value(self, mutation_context):
        if isinstance(self.child, int):
            return super().get_value(mutation_context)
        else:
            return self.child.get_value(mutation_context)

    @override
    def encode(self, value, mutation_context):
        if isinstance(self.child, int):
            return super().encode(value, mutation_context)
        else:
            return b"\x00" + self.child.encode(value, mutation_context)
