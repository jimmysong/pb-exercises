from unittest import TestCase

from bloomfilter import (
    BloomFilter,
    BIP37_CONSTANT,
)
from ecc import PrivateKey
from helper import (
    bit_field_to_bytes,
    bytes_to_bit_field,
    decode_base58,
    hash160,
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    murmur3,
)
from merkleblock import (
    MerkleBlock,
    MerkleTree,
)
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
    FILTERED_BLOCK_DATA_TYPE,
)
from script import p2pkh_script
from tx import (
    Tx,
    TxIn,
    TxOut,
)


def add(self, item):
    for i in range(self.function_count):
        seed = i * BIP37_CONSTANT + self.tweak
        h = murmur3(item, seed=seed)
        bit = h % (self.size * 8)
        self.bit_field[bit] = 1


def filterload(self, flag=1):
    payload = encode_varint(self.size)
    payload += self.filter_bytes()
    payload += int_to_little_endian(self.function_count, 4)
    payload += int_to_little_endian(self.tweak, 4)
    payload += int_to_little_endian(flag, 1)
    return payload


def serialize(self):
    result = encode_varint(len(self.data))
    for data_type, identifier in self.data:
        result += int_to_little_endian(data_type, 4)
        result += identifier[::-1]
    return result


def is_valid(self):
    flag_bits = bytes_to_bit_field(self.flags)
    hashes = [h[::-1] for h in self.hashes]
    merkle_tree = MerkleTree(self.total)
    merkle_tree.populate_tree(flag_bits, hashes)
    return merkle_tree.root()[::-1] == self.merkle_root


class Session8Test(TestCase):

    def test_apply(self):
        BloomFilter.add = add
        BloomFilter.filterload = filterload
        GetDataMessage.serialize = serialize
        MerkleBlock.is_valid = is_valid

    def test_example_1(self):
        bit_field_size = 10
        bit_field = [0] * bit_field_size
        h = hash256(b'hello world')
        bit = int.from_bytes(h, 'big') % bit_field_size
        bit_field[bit] = 1
        self.assertEqual(bit_field, [0, 0, 0, 0, 0, 0, 0, 0, 0, 1])

    def test_example_2(self):
        bit_field_size = 10
        bit_field = [0] * bit_field_size
        for item in (b'hello world', b'goodbye'):
            h = hash256(item)
            bit = int.from_bytes(h, 'big') % bit_field_size
            bit_field[bit] = 1
        self.assertEqual(bit_field, [0, 0, 1, 0, 0, 0, 0, 0, 0, 1])

    def test_example_3(self):
        bit_field_size = 10
        bit_field = [0] * bit_field_size
        for item in (b'hello world', b'goodbye'):
            for hash_function in (hash256, hash160):
                h = hash_function(item)
                bit = int.from_bytes(h, 'big') % bit_field_size
                bit_field[bit] = 1
        self.assertEqual(bit_field, [1, 1, 1, 0, 0, 0, 0, 0, 0, 1])

    def test_example_4(self):
        field_size = 2
        num_functions = 2
        tweak = 42
        bit_field_size = field_size * 8
        bit_field = [0] * bit_field_size
        for phrase in (b'hello world', b'goodbye'):
            for i in range(num_functions):
                seed = i * BIP37_CONSTANT + tweak
                h = murmur3(phrase, seed=seed)
                bit = h % bit_field_size
                bit_field[bit] = 1
        self.assertEqual(bit_field, [0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0])

    def test_exercise_1(self):
        field_size = 10
        function_count = 5
        tweak = 99
        items = (b'Hello World', b'Goodbye!')
        bit_field_size = field_size * 8
        bit_field = [0] * bit_field_size
        for item in items:
            for i in range(function_count):
                seed = i * BIP37_CONSTANT + tweak
                h = murmur3(item, seed=seed)
                bit = h % bit_field_size
                bit_field[bit] = 1
        self.assertEqual(bit_field_to_bytes(bit_field).hex(), '4000600a080000010940')

    def test_exercise_2(self):
        block_hash = bytes.fromhex('0000000053787814ed9dd8c029d0a0a9af4ab8ec0591dc31bdc4ab31fae88ce9')
        passphrase = b'Jimmy Song Programming Blockchain'  # FILL THIS IN
        secret = little_endian_to_int(hash256(passphrase))
        private_key = PrivateKey(secret=secret)
        addr = private_key.point.address(testnet=True)
        filter_size = 30
        filter_num_functions = 5
        filter_tweak = 90210  # FILL THIS IN
        h160 = decode_base58(addr)
        bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)
        bf.add(h160)
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True, logging=False)
        node.handshake()
        node.send(b'filterload', bf.filterload())
        getdata = GetDataMessage()
        getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)
        node.send(getdata.command, getdata.serialize())
        envelope = node.wait_for_commands([b'merkleblock'])
        envelope = node.wait_for_commands([b'tx'])
        self.assertEqual(envelope.payload.hex(), '0100000002a663815ab2b2ba5f53e442f9a2ea6cc11bbcd98fb1585e48a134bd870dbfbd6a000000006a47304402202151107dc2367cf5a9e2429cde0641c252374501214ce52069fbca1320180aa602201a43b5d4f91e48514c00c01521dc04f02c57f15305adc4eaad01c418f6e7a1180121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6effffffff618b00a343488bd62751cf21f368ce3be76e3a0323fdc594a0d24f27a1155cd2000000006a473044022024c4dd043ab8637c019528b549e0b10333b2dfa83e7ca66776e401ad3fc31b6702207d4d1d73ac8940c59c57c0b7daf084953324154811c10d06d0563947a88f99b20121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6effffffff0280969800000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788aca0ce6594000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000')

    def test_exercise_4(self):
        last_block_hex = '000000000d65610b5af03d73ed67704713c9b734d87cf4b970d39a0416dd80f9'
        last_block = bytes.fromhex(last_block_hex)
        secret = little_endian_to_int(hash256(b'Jimmy Song Programming Blockchain'))
        private_key = PrivateKey(secret=secret)
        addr = private_key.point.address(testnet=True)
        h160 = decode_base58(addr)
        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
        self.assertEqual(addr, target_address)
        filter_size = 30
        filter_num_functions = 5
        filter_tweak = 90210  # FILL THIS IN
        target_h160 = decode_base58(target_address)
        target_script = p2pkh_script(target_h160)
        fee = 5000  # fee in satoshis
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True, logging=False)
        bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)
        bf.add(h160)
        node.handshake()
        node.send(b'filterload', bf.filterload())
        getheaders_message = GetHeadersMessage(start_block=last_block)
        node.send(getheaders_message.command, getheaders_message.serialize())
        headers_envelope = node.wait_for_commands([HeadersMessage.command])
        stream = headers_envelope.stream()
        headers = HeadersMessage.parse(stream)
        get_data_message = GetDataMessage()
        for block in headers.blocks:
            self.assertTrue(block.check_pow())
            if last_block is not None:
                self.assertEqual(block.prev_block, last_block)
            last_block = block.hash()
            get_data_message.add_data(FILTERED_BLOCK_DATA_TYPE, last_block)
        node.send(get_data_message.command, get_data_message.serialize())
        prev_tx = None
        while prev_tx is None:
            envelope = node.wait_for_commands([b'merkleblock', b'tx'])
            stream = envelope.stream()
            if envelope.command == b'merkleblock':
                mb = MerkleBlock.parse(stream)
                self.assertTrue(mb.is_valid())
            else:
                prev = Tx.parse(stream, testnet=True)
                for i, tx_out in enumerate(prev.tx_outs):
                    if tx_out.script_pubkey.address(testnet=True) == addr:
                        prev_tx = prev.hash()
                        prev_index = i
                        prev_amount = tx_out.amount
                        break
        tx_in = TxIn(prev_tx, prev_index)
        output_amount = prev_amount - fee
        tx_out = TxOut(output_amount, target_script)
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        tx_obj.sign_input(0, private_key)
        self.assertEqual(tx_obj.serialize().hex(), '010000000194e631abb9e1079ec72a1616a3aa0111c614e65b96a6a4420e2cc6af9e6cc96e000000006a47304402203cc8c56abe1c0dd043afa9eb125dafbebdde2dd4cd7abf0fb1aae0667a22006e02203c95b74d0f0735bbf1b261d36e077515b6939fc088b9d7c1b7030a5e494596330121021cdd761c7eb1c90c0af0a5963e94bf0203176b4662778d32bd6d7ab5d8628b32ffffffff01f8829800000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000')
