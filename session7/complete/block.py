from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase, skip

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
)


class Proof:

    def __init__(self, merkle_root, tx_hash, index, complementary_hashes):
        self.merkle_root = merkle_root
        self.tx_hash = tx_hash
        self.index = index
        self.complementary_hashes = complementary_hashes

    def verify(self):
        '''Returns whether this proof is valid'''
        current = self.tx_hash[::-1]
        for i, complementary_hash in enumerate(self.complementary_hashes):
            if (self.index >> i) & 1 == 1:
                current = double_sha256(complementary_hash + current)
            else:
                current = double_sha256(current + complementary_hash)
        return current == self.merkle_root[::-1]


class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes
        self.merkle_tree = None

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''
        # version - 4 bytes, little endian
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        '''Returns the 80 byte block header'''
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        '''Returns the double-sha256 interpreted little endian of the block'''
        return double_sha256(self.serialize())[::-1]

    def bip9(self):
        '''Returns whether this block is signaling readiness for BIP9'''
        # BIP9 is signalled if the top 3 bits are 001
        return self.version >> 29 == 0b001

    def bip91(self):
        '''Returns whether this block is signaling readiness for BIP91'''
        # BIP91 is signalled if the top 5th bit from the right is 1
        return (self.version >> 4) & 1 == 1
    
    def bip141(self):
        '''Returns whether this block is signaling readiness for BIP141'''
        # BIP91 is signalled if the top 2nd bit from the right is 1
        return (self.version >> 1) & 1 == 1

    def target(self):
        '''Returns the proof-of-work target based on the bits'''
        # note bits is in little-endian and the first byte is the exponent
        # the other three bytes are the coefficient.
        # the formula is:
        # coefficient * 2**(8*(exponent-3))
        exponent = self.bits[-1]
        coefficient = little_endian_to_int(self.bits[:-1])
        return coefficient * 2**(8*(exponent - 3))

    def difficulty(self):
        '''Returns the block difficulty based on the bits'''
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        exponent = 0x1d
        minimum_target = 0xffff * 2**(8*(0x1d-3))
        return minimum_target / self.target()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # You will need to get the hash of this block and interpret it
        # as an integer. If the hash of the block is lower, pow is good.
        # hint: int.from_bytes('', 'big')
        s256 = self.hash()
        return int.from_bytes(s256, 'big') < self.target()

    def validate_merkle_root(self):
        '''Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        Has side effect of setting self.merkle_tree.
        '''
        if self.tx_hashes is None:
            return None
        self.merkle_tree = []
        current_level = [x[::-1] for x in self.tx_hashes]
        if len(current_level) != 1 and len(current_level) % 2 == 1:
            current_level.append(current_level[-1])
        self.merkle_tree.append(current_level)
        while len(current_level) > 1:
            next_level = [double_sha256(current_level[i] + current_level[i+1]) for i in range(0, len(current_level), 2)]
            if len(next_level) != 1 and len(next_level) % 2 == 1:
                next_level.append(next_level[-1])
            self.merkle_tree.append(next_level)
            current_level = next_level
        return current_level[0][::-1] == self.merkle_root

    def create_merkle_proof(self, tx_hash):
        if self.tx_hashes is None:
            return None
        elif self.merkle_tree is None:
            self.validate_merkle_root()
        item_num = self.merkle_tree[0].index(tx_hash[::-1])
        index = item_num
        current = self.merkle_tree[0][item_num]
        complementary_hashes = []
        for level in self.merkle_tree[:-1]:
            if item_num % 2 == 0:
                current = double_sha256(current + level[item_num+1])
                complementary_hashes.append(level[item_num + 1])
            else:
                current = double_sha256(level[item_num-1] + current)
                complementary_hashes.append(level[item_num - 1])
            item_num = item_num // 2
        # sanity check
        if current != self.merkle_tree[-1][0]:
            raise RuntimeError('merkle tree looks invalid')
        return Proof(self.merkle_root, tx_hash, index, complementary_hashes)


class BlockTest(TestCase):

    def test_parse(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.version, 0x20000002)
        want = unhexlify('000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e')
        self.assertEqual(block.prev_block, want)
        want = unhexlify('be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b')
        self.assertEqual(block.merkle_root, want)
        self.assertEqual(block.timestamp, 0x59a7771e)
        self.assertEqual(block.bits, unhexlify('e93c0118'))
        self.assertEqual(block.nonce, unhexlify('a4ffd71d'))

    def test_serialize(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.serialize(), block_raw)

    def test_hash(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.hash(), unhexlify('0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523'))


    def test_bip9(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip9())
        block_raw = unhexlify('0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip9())

    def test_bip91(self):
        block_raw = unhexlify('1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip91())
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip91())

    def test_bip141(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip141())
        block_raw = unhexlify('0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip141())

    def test_target(self):
        block_raw = unhexlify('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.target(), 0x13ce9000000000000000000000000000000000000000000)
        self.assertEqual(int(block.difficulty()), 888171856257)

    def test_check_pow(self):
        block_raw = unhexlify('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.check_pow())
        block_raw = unhexlify('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0')
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.check_pow())

    def test_validate_merkle_root(self):
        hashes_hex = [
            'f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1',
            'c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1',
            'b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3',
            '8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d',
            'ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910',
            '61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d',
            'fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881',
            '77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df',
            '59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8',
            '7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195',
            '08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e',
            'f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1',
        ]
        hashes = [unhexlify(x) for x in hashes_hex]
        block = Block(
            version=536870912,
            prev_block=unhexlify('0000000000000152991da56898d576fb19395e91e77395dcca08db95789fb1fc'),
            merkle_root=unhexlify('d6ee6bc8864e5c08a5753d3886148fb1193d4cd2773b568d5df91acc8babbcac'),
            bits=unhexlify('16ca061a'),
            timestamp=1504235409,
            nonce=unhexlify('00000000'),
            tx_hashes=hashes,
        )
        self.assertTrue(block.validate_merkle_root())

    def test_merkle_proof(self):
        hashes_hex = [
            'f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1',
            'c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1',
            'b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3',
            '8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d',
            'ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910',
            '61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d',
            'fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881',
            '77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df',
            '59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8',
            '7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195',
            '08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e',
            'f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1',
        ]
        hashes = [unhexlify(x) for x in hashes_hex]
        block = Block(
            version=536870912,
            prev_block=unhexlify('0000000000000152991da56898d576fb19395e91e77395dcca08db95789fb1fc'),
            merkle_root=unhexlify('d6ee6bc8864e5c08a5753d3886148fb1193d4cd2773b568d5df91acc8babbcac'),
            bits=unhexlify('16ca061a'),
            timestamp=1504235409,
            nonce=unhexlify('00000000'),
            tx_hashes=hashes,
        )
        h = hashes[7]
        proof = block.create_merkle_proof(h)
        self.assertTrue(proof.verify())
