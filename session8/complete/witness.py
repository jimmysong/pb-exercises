from io import BytesIO

from helper import (
    encode_varint,
    encode_varstr,
    read_varint,
    read_varstr,
)
from script import Script


class Witness:
    def __init__(self, items=None):
        self.items = items or []

    def __repr__(self):
        result = ""
        for item in self.items:
            if item == b"":
                result += "<null> "
            else:
                result += f"{item.hex()} "
        return result

    def __getitem__(self, key):
        return self.items[key]

    def __len__(self):
        return len(self.items)

    def clone(self):
        return self.__class__(self.items[:])

    def serialize(self):
        result = encode_varint(len(self))
        for item in self.items:
            result += encode_varstr(item)
        return result

    @classmethod
    def parse(cls, s):
        num_items = read_varint(s)
        items = []
        for _ in range(num_items):
            items.append(read_varstr(s))
        return cls(items)
