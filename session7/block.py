from io import BytesIO
from unittest import TestCase

from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
    read_varint,
    target_to_bits,
)
from tx import Tx


MAX_TARGET = 0xFFFF * 256 ** (0x1D - 3)
TWO_WEEKS = 60 * 60 * 24 * 14


class Block:
    command = b"block"

    def __init__(
        self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes
        self.merkle_tree = None

    def __eq__(self, other):
        return self.hash() == other.hash()

    @classmethod
    def parse_header(cls, s):
        """Takes a byte stream and parses a block. Returns a Block object"""
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    @classmethod
    def parse(cls, s, network="mainnet"):
        """Takes a byte stream and parses a block. Returns a Block object"""
        b = cls.parse_header(s)
        num_txs = read_varint(s)
        b.txs = []
        b.tx_hashes = []
        b.tx_lookup = {}
        for _ in range(num_txs):
            t = Tx.parse(s, network=network)
            b.txs.append(t)
            b.tx_hashes.append(t.hash())
            b.tx_lookup[t.hash()] = t
        return b

    def serialize(self):
        """Returns the 80 byte block header"""
        # version - 4 bytes, little endian
        result = int_to_little_endian(self.version, 4)
        # prev_block - 32 bytes, little endian
        result += self.prev_block[::-1]
        # merkle_root - 32 bytes, little endian
        result += self.merkle_root[::-1]
        # timestamp - 4 bytes, little endian
        result += int_to_little_endian(self.timestamp, 4)
        # bits - 4 bytes
        result += self.bits
        # nonce - 4 bytes
        result += self.nonce
        return result

    def hash(self):
        """Returns the hash256 interpreted little endian of the block"""
        # serialize
        s = self.serialize()
        # hash256
        h256 = hash256(s)
        # reverse
        return h256[::-1]

    def id(self):
        """Human-readable hexadecimal of the block hash"""
        return self.hash().hex()

    def bip9(self):
        """Returns whether this block is signaling readiness for BIP9"""
        # BIP9 is signalled if the top 3 bits are 001
        # remember version is 32 bytes so right shift 29 (>> 29) and see if
        # that is 001
        return self.version >> 29 == 0b001

    def bip112(self):
        """Returns whether this block is signaling readiness for BIP112"""
        # BIP112 is signalled if the first bit from the right is 1
        # shift 0 bits to the right and see if the last bit is 1
        return self.version >> 0 & 1 == 1

    def bip141(self):
        """Returns whether this block is signaling readiness for BIP141"""
        # BIP141 is signalled if the 2nd bit from the right is 1
        # shift 1 bit to the right and see if the last bit is 1
        return self.version >> 1 & 1 == 1

    def bip341(self):
        """Returns whether this block is signaling readiness for BIP341"""
        # BIP341 is signalled if the 3rd bit from the right is 1
        # shift 2 bits to the right and see if the last bit is 1
        return self.version >> 2 & 1 == 1

    def bip91(self):
        """Returns whether this block is signaling readiness for BIP91"""
        # BIP91 is signalled if the 5th bit from the right is 1
        # shift 4 bits to the right and see if the last bit is 1
        return self.version >> 4 & 1 == 1

    def target(self):
        """Returns the proof-of-work target based on the bits"""
        # last byte is exponent
        exponent = self.bits[-1]
        # the first three bytes are the coefficient in little endian
        coefficient = little_endian_to_int(self.bits[:-1])
        # the formula is:
        # coefficient * 256**(exponent-3)
        return coefficient * 256 ** (exponent - 3)

    def difficulty(self):
        """Returns the block difficulty based on the bits"""
        # note difficulty is MAX_TARGET / (self's target)
        return MAX_TARGET / self.target()

    def check_pow(self):
        """Returns whether this block satisfies proof of work"""
        # get the hash256 of the serialization of this block
        h256 = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(h256)
        # return whether this integer is less than the target
        return proof < self.target()

    def new_bits(self, beginning_block):
        """Calculates the new bits for a 2016-block epoch.
        Assumes current block is the last of the 2016-block epoch.
        Requires the first block of the epoch."""
        # calculate the time differential
        time_differential = self.timestamp - beginning_block.timestamp
        # if the time differential is greater than 8 weeks, set to 8 weeks
        if time_differential > TWO_WEEKS * 4:
            time_differential = TWO_WEEKS * 4
        # if the time differential is less than half a week, set to half a week
        if time_differential < TWO_WEEKS // 4:
            time_differential = TWO_WEEKS // 4
        # the new target is the current target * time differential / two weeks
        new_target = self.target() * time_differential // TWO_WEEKS
        # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
        if new_target > MAX_TARGET:
            new_target = MAX_TARGET
        # convert the new target to bits using the target_to_bits function
        return target_to_bits(new_target)

    def validate_merkle_root(self):
        """Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        """
        # reverse all the transaction hashes (self.tx_hashes)
        # get the Merkle Root
        # reverse the Merkle Root
        # return whether self.merkle root is the same as
        # the reverse of the calculated merkle root
        raise NotImplementedError


GENESIS_BLOCKS = {
    "mainnet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
            )
        )
    ),
    "testnet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"
            )
        )
    ),
    "signet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203"
            )
        )
    ),
}


class BlockTest(TestCase):
    def test_parse(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertEqual(block.version, 0x20000002)
        want = bytes.fromhex(
            "000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e"
        )
        self.assertEqual(block.prev_block, want)
        want = bytes.fromhex(
            "be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b"
        )
        self.assertEqual(block.merkle_root, want)
        self.assertEqual(block.timestamp, 0x59A7771E)
        self.assertEqual(block.bits, bytes.fromhex("e93c0118"))
        self.assertEqual(block.nonce, bytes.fromhex("a4ffd71d"))

    def test_serialize(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertEqual(block.serialize(), block_raw)

    def test_hash(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertEqual(
            block.hash(),
            bytes.fromhex(
                "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523"
            ),
        )

    def test_bip9(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.bip9())
        block_raw = bytes.fromhex(
            "0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.bip9())

    def test_bip112(self):
        block_raw = bytes.fromhex(
            "010000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.bip112())
        block_raw = bytes.fromhex(
            "0400002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.bip112())

    def test_bip141(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.bip141())
        block_raw = bytes.fromhex(
            "0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.bip141())

    def test_bip341(self):
        block_raw = bytes.fromhex(
            "040000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.bip341())
        block_raw = bytes.fromhex(
            "0100002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.bip341())

    def test_bip91(self):
        block_raw = bytes.fromhex(
            "1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.bip91())
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.bip91())

    def test_target(self):
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertEqual(
            block.target(), 0x13CE9000000000000000000000000000000000000000000
        )
        self.assertEqual(int(block.difficulty()), 888171856257)

    def test_check_pow(self):
        block_raw = bytes.fromhex(
            "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertTrue(block.check_pow())
        block_raw = bytes.fromhex(
            "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0"
        )
        stream = BytesIO(block_raw)
        block = Block.parse_header(stream)
        self.assertFalse(block.check_pow())

    def test_new_bits(self):
        block1 = Block.parse_header(
            BytesIO(
                bytes.fromhex(
                    "000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3"
                )
            )
        )
        block2 = Block.parse_header(
            BytesIO(
                bytes.fromhex(
                    "02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474"
                )
            )
        )
        want = bytes.fromhex("308d0118")
        self.assertEqual(block2.new_bits(block1), want)

    def test_validate_merkle_root(self):
        hashes_hex = [
            "f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1",
            "c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1",
            "b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3",
            "8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d",
            "ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910",
            "61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d",
            "fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881",
            "77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df",
            "59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8",
            "7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195",
            "08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e",
            "f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1",
        ]
        hashes = [bytes.fromhex(x) for x in hashes_hex]
        stream = BytesIO(
            bytes.fromhex(
                "00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000"
            )
        )
        block = Block.parse_header(stream)
        block.tx_hashes = hashes
        self.assertTrue(block.validate_merkle_root())
