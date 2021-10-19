from buidl.helper import (
    encode_varint,
    encode_varstr,
    read_varint,
    read_varstr,
)


class Witness:
    def __init__(self, items=None):
        self.items = items or []

    def __repr__(self):
        result = ""
        for item in self.items:
            result += "{} ".format(item.hex())
        return result

    @classmethod
    def parse(cls, s):
        num_items = read_varint(s)
        items = []
        for _ in range(num_items):
            items.append(read_varstr(s))
        return cls(items)

    def __len__(self):
        return len(self.items)

    def serialize(self):
        result = encode_varint(len(self))
        for item in self.items:
            if len(item) == 1:
                result += item
            else:
                result += encode_varstr(item)
        return result
