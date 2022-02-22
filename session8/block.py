from io import BytesIO
from unittest import TestCase

from helper import (
    decode_base58,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
    read_varint,
    target_to_bits,
)
from script import p2pkh_script
from tx import Tx


MAX_TARGET = 0xFFFF * 256 ** (0x1D - 3)
TWO_WEEKS = 60 * 60 * 24 * 14


class Block:
    command = b"block"
    define_network = True

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

    def get_tx_out_scripts(self):
        if not self.txs:
            return []
        for t in self.txs:
            for tx_out in t.tx_outs:
                if not tx_out.script_pubkey.has_op_return():
                    yield (tx_out.script_pubkey)

    def validate_merkle_root(self):
        """Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        """
        # reverse all the transaction hashes (self.tx_hashes)
        hashes = [h[::-1] for h in self.tx_hashes]
        # get the Merkle Root
        root = merkle_root(hashes)
        # reverse the Merkle Root
        # return whether self.merkle root is the same as
        # the reverse of the calculated merkle root
        return root[::-1] == self.merkle_root

    def get_transactions(self, script_pubkey):
        """Returns a list of transactions that have the given ScriptPubKey as an output"""
        # return if we don't have a self.txs property
        # initialize the tx list we'll send back
        # loop through all the txs in this block
        # loop through all the tx_outs in this tx
        # if this TxOut has the script_pubkey we're looking for
        #  add to the tx list
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
        want = bytes.fromhex("80df6217")
        self.assertEqual(block1.new_bits(block2), want)

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

    def test_get_transactions(self):
        hex_block = "0000002054467a8669c273758fd01bc9a5abf84a16afeb755d04192713a09b14a80000001b2dde020d42c4c1c13949d79b00bc6a6ce8b1b2a7aa673c5883d8c6cbaa61520300ff61015f011e5d6828002c01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0403cc2901feffffff02920f062a0100000016001481113cad52683679a83e76f76f84a4cfe36f75010000000000000000776a24aa21a9ede5573b67f0a45b071443de3791a7faa31ef74617a105092270743ec8091dbd0d4c4fecc7daa24900473044022000e6d4b3a2c00498f41e5b464f270d93ca166f9b3efb1ed67b7e1f37c7a51f5b0220776171c650f4a8d15c2461f08ca980059866f1aa1104d7bff00947a23245dcdb01000000000002000000012fe63105d076945c2b1f4b10ef1fb1447cd5b78c27de84f08d4e4ffe70521d4c0000000000ffffffff0158800400000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260000000000200000001e6e895721d0e4a6504194ac8fbcb5963a25ce51502e8b6ace42ae03be4c30f3d0000000000ffffffff015a41ac05000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600000000002000000016592d2aa7bf2554a580494495fea9631b04e94c6ec5640913ab3d31fcf85ee830000000000ffffffff01d220821d000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260000000000200000001cbeb5cadde086547056edcb2d28c27886e48a3f3e068816e3e6df7ff2fa0b9070000000000ffffffff0158800400000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600000000002000000011d947fef4eaef0d141904df0c77dfbb2bd1603ab035dda603da8555f4e9e3cce0000000000ffffffff01c81a8100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260000000000200000001cb71af42925425c079651a3d43ba45b7ba9b9de35116c3d180dfa4dfd0698c740100000000feffffff02a086010000000000225120fa878ef91309e4f5a3e339a1ad3d7be07d621989081dfed63d4b09f8375a5ab5f7e4332f560600001600145c6257d3a5410ac92e9cdd5fbce1cf802c169ee6cb2901000200000001d41d7a7916051fea79105f37e0ea69d6291beda2eeb7e7681460874831793ecd0000000000feffffff02a08601000000000022512012af50ff238072e03fde04f913abeba0115d8a54a5d7fce25e8c4299230d9526a4eaec9e50060000160014f30813def9472e98057168c30ed1af19af1c0c95cb2901000200000001c31cf6f37fc65143f87c37194748e88fe3e42729009a5315e9ee2abb846610e40100000000feffffff024663eb9e500600001600143d81f6f484f155cd8cc9f720d26f79b2e32ee99da0860100000000002251200b0f91e3628b82e264903d46a20264edd1e5ff409b3908d1d91317040f7a98b1cb2901000200000001d4e65bbfff0676dfd5be0e8b75926470b23ab362668b8556988891bcba622b950100000000feffffff02ee7ebc8759060000160014533f2bf2864799fdb8ede0bd81a38119bb355d26a0860100000000002251207f2f9ba8a9c64abb9b581c9f469bbb46878acd8833285ac99ec8e14c5045d185cb29010002000000014f0f38db29e0d3d73ad8da7e06be79baf1b97479b428ce9f469a593a237b16910100000000feffffff02a086010000000000225120ca9a05a55b9a772b351ac1932617d3d34482d5e4a9097d996a102985d4ffea27ac59459d54060000160014da88916a0ab55fea9e79afe12aee30267da4e7b9cb2901000200000001143a450aca614e0da37069eeb86306841a8d0e77c56045317266bc1579186f730000000000feffffff0273e5e8ab58060000160014ced83612f894efc20582b3d572481b5fa2c0017aa08601000000000022512089d160fffd13188eb62263148db575fa4ea73f3ba25b58dbb3cd1ab695c9cbb2cb29010002000000011f3134fd8fab58a24a3021403cd623eef04711e6616befa950b5dec7213d328b0000000000feffffff02a086010000000000225120434e8f260ef69ca386025efc581318feb5acb1459657d866fd407de7c2a09437e8dbe99e50060000160014477dbe556ecfe9652cb19e36a2627d2d43bb948fcb2901000200000001cbfb785a79ba55f12a9d97dba0a3df01df4df1e2aaad4b1c02e347f9fffe98220100000000feffffff02a086010000000000225120316b4ebf54d3d833d09b30df3fd4a9876c73027bd171cbac725e2b4bd2704500cafbe277530600001600140cd8f55378a7a647b414fe9a48e717734cd2c044cb2901000200000001f0d044e3b7468a8140652afd191beb3bb53443f8bdf962d08044876bf361914c0100000000feffffff02a0860100000000002251206ed63f98db432da77efeffb4b876da0cb7084ecd5be788af00c14108d652b10cf1364e095a06000016001421acc2c1f39dbd75a8d45f86ddea307a2826d2fccb29010002000000014b28c3eefae1c227c542bf151ae70d5ab33f9ad2d1e11083fbe5935297c577520000000000feffffff0200dfde4b5a06000016001471677f3151151c64042de0f0192f01a82305d76aa086010000000000225120e714a9164518744091387d7966193c95ed3745d742e20620507d5106ae144cc9cb29010002000000018c048d904585c47e91c85ca32b4c69ff140953795011ca5a3080062bee37cc220000000000feffffff02a0860100000000002251201e8d6937399687e8eea2f74841454fa4a7c93b7155ba74ea5c3152b203b964f5f63f8fdb55060000160014112a98837f20a1516d83be29189a43b353e424fccb2901000200000001279f4ac4eecdd2eac6eb11f878b638c92859909b82fbdc2e5d0f07f18c8cb1ec0000000000feffffff027910d85d59060000160014cc0d2a47189476a50b1a34defa0df7836517fcdaa086010000000000225120bfa3b33086e985a9812baba7d1d2d13aaaef4e439c5b3ef774e7bf5edcd59022cb2901000200000001ab149cf924e1bc4390fece6e5cf796e9a83136cf2dd72bbf392da088312e75af0100000000feffffff0265c5dcf2570600001600141c4827f713b8276dbde2f197d1022b92bf56146fa08601000000000022512001a4fa1d189bbf4959f0cdc55b706afadbf2169b9535c8540e557caa7bcce595cb2901000200000001d1056e74d97c01355899c23eff9969781a2c363c8d0c749dd93684a291ac85370100000000feffffff02a0860100000000002251205e11df8f4f16da643148b72ce9346b134ec390946d8a8993a47cb298b0ca2080725aaf0f55060000160014868c6315d79bf405b76921dee06477e6bcde111dcb290100020000000134817492944f7bafe9b10636675b8364454c4c45b66a90259e4fea32dadb78550100000000feffffff02a08601000000000022512044fdfcccf66c5a24bf910c07af0b168f79e56c63b6d7fe232e59a3d669589ecc327ac33059060000160014fc5ce9f27e6972794ae74cf0cd830d2be4092914cb2901000200000001ec7b8576e37e80c688f1424d77b6d1c4e1a742cb9852b8e5032a7f1bd6defd310000000000feffffff025b91416b58060000160014a523585fb05d1883e56a56f369e5c20276ac090da086010000000000225120da07ab163a80f44f0a430c1ce57de69c593aa58407bb437fa3074c13661ae809cb2901000200000001ba498b05c1782e503681a55b7ba61ff86491f3e413551a4c48795c2d49c6694c0100000000feffffff02a47215224f0600001600141de87588bd687f4f206f610737c1457c84f37ff3a086010000000000160014b2d01e2295a1cb13b0983a087f3969f10b72c40acb29010002000000010663b71eb994787921529e70791b855de12a5c4e5374f824e3e0d18b6ac8bbc30000000000feffffff0246eb13224f0600001600148891d23b7b086b04e38ff318b5979a3064b05fc6a0860100000000002251207230419125f8a148802e93f70e1ce558e138687368f3b8ba95a0df344862b558cb290100020000000138cfe7202ff25ef3d8ab3725b3dfa62c55b521dfa701525b99da446fc07ec9bd0000000000feffffff02a086010000000000225120919da0cf946bb49c42b879f70f1b1080f201ba26a42e7332dfcd625bf2d91c5ae86312224f060000160014d7538d9a0d92181c619dd9f5109419ae4c88a1b9cb290100020000000117d64e804b4c8a17f01e0c842228fd67bc4ba4c01040d768ef2eb33f9db51c070000000000feffffff02a086010000000000160014c2330acf8d4152edae2196b6d5773b8f82074b69d840483752060000160014884d9f9fabae3f4a125e28b0968a6d728601120fc72901000200000001920094a4d9bfa2e2e8ae843786966dbb43c4394dd7f3dd683be8976d86e4926e0000000000feffffff02a08601000000000016001480befc464f0024acaa9215631b38873d0ac89949355b902e57060000160014105d3f3cfb1a40c95b50ecc1bac529d4286dbf4ecb290100020000000126d262e91df7d32a7280d8ed74ca7218e03a221c520a9aded12334b7161b23900000000000feffffff02a0860100000000001600141f8c100db400649a15028884989aeb118f37733b97546e8f51060000160014e4097b006d98eb4a08fad0c44d594fd1440ea63aca2901000200000001d210362e4fbee7b3db063337491bf322ce76f2f4f90794bbbc2cb086adb96b9b0100000000feffffff02a0860100000000001600146e680bafc163dc5dbdd81e31a06f068e38ec26ed48cd6c8f5106000016001417808b83c92b6cecb522961f8327a35568a91cdacb29010002000000017aeb80dd277027a729d42b352247009f84ea1b66547d5362258ed1523aa0cdce0100000000feffffff02a086010000000000160014c507f86bd30150e05d3732d42d3ce922d01d99f2f9456b8f510600001600140911d0e530739a06a44fe69e29d9ad223a38aa3cc42901000200000001bc7793b9bc24f3fb597fad4b775f2f185f6afee043f6b9842d592e5a42b182de0000000000feffffff02a086010000000000160014315c4f16fef4e22c223a769aa8fd6867c6293f62e015a8a957060000160014b6587bbe85244b1a20df9568afa3f9209c82d4af8329010002000000017cdbaa04b35df38d2f05a6d19a54175a09c2198f5e54c8b7a338d99440a19f4e0100000000feffffff02a086010000000000160014dbbc2b282691fd3719a79caf4a49ddd67fee28ad0fd4bb055906000016001484270ff25095ddba3d5a00bc919154f9343b105fcb29010002000000015b066e7533c1a5ec54714c7a21bd7f076466f1f61e530b2da1aa3524a7c78fbb0000000000feffffff020152d2d1560600001600144bafcc944e708c49e1ccea39acbed0981d120f85a086010000000000160014435f310d0b9deae1c19813079f07b2afe5afb64fcb2901000200000001318744a747199341946c0b97f1a5b3468fde55fdf8f11e0d6aa60ec4c2e87d3f0100000000feffffff020dce3ee859060000160014d19d47f16fdd6d0325485896530e9255715c4d07a08601000000000016001470a8420430f380bcf6933e60027b4a773a75fd95cb29010002000000019465938c09a00c621aa7ee2712116bfe5a0f0d42d130f6959e2be19c6d03eba60000000000feffffff02a08601000000000016001473934f9278a760b9795066158d3630b15d5a32ea3d6983e452060000160014a7ccb38ec277aaf30f7553220458d54349634d2ecb29010002000000011d1c4cca90bb7c757d84454a0c738734108e23dd93909f44877923e7ea7ea11e0000000000feffffff02a08601000000000016001484a744b6e38e153c87b61452104bee13c4ca8d20edfaa52b5a060000160014a84de0bf8ea9f5ee9a85158b90644e958e241df5cb29010002000000012687943e8c15b4c71c66e182fa225015fb4f09dbb32311d576bbc25dcd9a26e10000000000feffffff02a0860100000000001600148466eda7d89f4663ddfc84e8ddf342097ccebbb7a77acb025406000016001477d9fd5d32663b59d7b278893cb63496bcf959b0cb290100020000000151bdd5acb05c0ca23abd4a2f2bb84ca319b0244ed6a9cbcad2c735e0b40a6a2f0000000000feffffff02a0860100000000001600149bdd6eca30b29af8a9fc2661df9499f069631bc4c158fc7f55060000160014c90a28ff70d7300a75ba91cfbb4601cd7a2a40bdcb29010002000000014d6fdb0b37d6545f633e0ebc3dd8f3699759abe73cb9fe067134ace6a74fba2e0000000000feffffff02cb46f06c5706000016001477ebe0154dbe3be34a8b797ac9eade414d361c56a0860100000000001600149435840d1df8cc3142b3fa519e9aa9408e3ab3d5cb29010002000000011f5a0ceb59c36f5d8a0e06ac1ab070529002f93685249d431a89ac3388aab1ad0100000000feffffff02a086010000000000160014db2f02e83928e236ec01f47d5c00e7f16062d365f19cb3c059060000160014ada543dffd084e435709e6cac3ebff88ed2ee164c829010002000000013e5760ef3f86bdd2d2364452be9315e0026e7bf694b0f689a090bebdb958002a0000000000feffffff02a0860100000000001600147a477a5eb627ce60fd6c3703840cbd3a0df219a8ca8ea274560600001600145e9a6bf26c3e70fee0f477da6e623c1386f072299b29010002000000019dbbf207d79e177a13143f682f081aeb7477615ec349aaa8db31926f7abfb9380000000000feffffff02ae0a46df580600001600142e44199f3ce728dafc7c511ce20c72e486893741a086010000000000160014bb670a0676005342c9c5431dd797f4fa9e89319acb290100020000000124b623d20899de530af9e2c04482c0b16ee63e1d1ecf8d58a8b975cdf91ee7b90000000000feffffff0207fd8927580600001600149d7d5935329a7fcddb33234a62fd2a0fb42e682fa086010000000000160014bf25b0006a436e65ce287e327051421765c3d3c8cb290100010000000181b0ad7cc5c3c09cee885623770e11bf75b8ba6b116200899232ada028ee0ced000000006a473044022028b72508fff22703396a78b4428ec64ad98c598ca4ac9c0d7da1f4a51442afd6022049bc6580793eb6ba15058bccbada80175547d558b74375e7dc4b2e3de54a0e00012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff01e1c70000000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000"
        stream = BytesIO(bytes.fromhex(hex_block))
        b = Block.parse(stream)
        address = "mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv"
        script_pubkey = p2pkh_script(decode_base58(address))
        txs = b.get_transactions(script_pubkey)
        self.assertEqual(len(txs), 1)
        self.assertEqual(
            txs[0].id(),
            "89b252427a527b955393aaaebe95f2d38c3367f9fd2415bf0fae3b4336fc7831",
        )
