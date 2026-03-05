from typing import override

import boofuzz


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
        fuzzable = False
        if child is not None and child.fuzzable:
            fuzzable = True
        super().__init__(
            name=name,
            fuzzable=fuzzable,
            *args,
            **kwargs,
        )

    @override
    def mutations(self, _default_value):
        if self.child is None:
            yield None
            return
        for mutation in self.child.mutations(self.child.original_value()):
            yield mutation

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
        return b"\x01" + self.child.encode(value, mutation_context)
