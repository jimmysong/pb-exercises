from block import Block


MAX_TARGET = 0xffff*256**(0x1d-3)
MAX_BITS = b'\xff\xff\x00\x1d'

with open('blockchain_headers', 'rb') as f:
    new_target=MAX_TARGET
    new_bits = MAX_BITS
    # read 2016 blocks
    while True:
        chunk = []
        for _ in range(2016):
            b = Block.parse(f)
            if b.bits != new_bits:
                print(b.prev_block.hex())
                raise RuntimeError("weird bits: {} {} {}".format(b.hash().hex(), b.bits.hex(), new_bits.hex()))
            chunk.append(b)

        first = chunk[0]
        final = chunk[-1]
        diff = final.timestamp - first.timestamp
        print(diff / (86400 * 14))
        if diff > 86400 * 56:
            diff = 86400 * 56
        elif diff < 86400 * 3.5:
            diff = int(86400*3.5)
        new_target = int(final.target() * diff / (86400*2*7))
        if new_target > MAX_TARGET:
            new_target = MAX_TARGET
        # convert target back to bits
        raw_bytes = new_target.to_bytes(32, 'big')
        while raw_bytes[0] == 0:
            raw_bytes = raw_bytes[1:]
        if raw_bytes[0] > 0x7f:
            exponent = len(raw_bytes) + 1
            coefficient = b'\x00' + raw_bytes[:2]
        else:
            exponent = len(raw_bytes)
            coefficient = raw_bytes[:3]
        new_bits_big_endian = bytes([exponent]) + coefficient
        new_bits = new_bits_big_endian[::-1]
        print(new_bits.hex())

