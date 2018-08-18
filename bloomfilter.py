from unittest import TestCase

from helper import int_to_little_endian


BIP37_CONSTANT = 0xfba4c795

# http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash
def murmur3(data, seed=0):
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
            ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2

        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64

    # tail
    k1 = 0

    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1

    # finalization
    h1 ^= length

    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)

    return h1 & 0xffffffff


class BloomFilter:

    def __init__(self, size, function_count, tweak):
        self.size = size
        self.filter = b'\x00' * self.size
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item):
        for i in range(self.function_count):
            # BIP0037 spec seed
            seed = i * BIP37_CONSTANT + self.tweak
            h = murmur3(item, seed=seed)
            # the bit we need to set
            bit = h % (self.size * 8)
            filter_index, bit_index = divmod(bit, 8)
            # now we set that particular bit
            if not self.is_set(bit):
                new_byte = self.filter[filter_index] | (1 << bit_index)
                self.filter = self.filter[:filter_index] + bytes([new_byte]) + self.filter[filter_index+1:]

    def is_set(self, bit):
        # check to see if the particular bit is set
        filter_index, bit_index = divmod(bit, 8)
        return self.filter[filter_index] & (1 << (bit_index)) != 0

    def filterload(self, flag=0):
        payload = bytes([self.size]) + self.filter
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        payload += int_to_little_endian(flag, 1)
        print(payload.hex())
        return payload
        
