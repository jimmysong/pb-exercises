from unittest import TestCase

from bloomfilter import BloomFilter, BIP37_CONSTANT
from ecc import PrivateKey
from helper import (
    bit_field_to_bytes,
    decode_base58,
    hash160,
    hash256,
    little_endian_to_int,
    murmur3,
)
from merkleblock import MerkleBlock
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
    FILTERED_BLOCK_DATA_TYPE,
)
from script import p2pkh_script
from tx import Tx, TxIn, TxOut


class Session8Test(TestCase):

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
        block_hash = bytes.fromhex('00000000000001fd16e986436252c023b2f9ba729319309189af9ab5be9d4ff9')
        passphrase = b'jimmy@programmingblockchain.com secret passphrase'  # FILL THIS IN
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
        self.assertEqual(envelope.payload.hex(), '02000000017556362f68c62760de4bb3d89cecfd1a8dcd0cf84d5eb12716120f6eb91b87c001000000171600140b93f828f96efe70b85006b51a6874c562d0cd73feffffff023b8d23e10300000017a91461cd953151a023c0746a57dacef36a35b06dc5ae87207e7500000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac6fe91500')

    def test_exercise_4(self):
        last_block_hex = '00000000000538d5c2246336644f9a4956551afb44ba47278759ec55ea912e19'
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
        start_block = bytes.fromhex(last_block_hex)
        getheaders_message = GetHeadersMessage(start_block=start_block)
        node.send(getheaders_message.command, getheaders_message.serialize())
        headers_envelope = node.wait_for_commands({HeadersMessage.command})
        stream = headers_envelope.stream()
        headers = HeadersMessage.parse(stream)
        last_block = None
        get_data_message = GetDataMessage()
        for block in headers.blocks:
            self.assertTrue(block.check_pow())
            if last_block is not None:
                self.assertEqual(block.prev_block, last_block)
            last_block = block.hash()
            get_data_message.add_data(FILTERED_BLOCK_DATA_TYPE, last_block)
        node.send(get_data_message.command, get_data_message.serialize())
        prev_tx, prev_index, prev_tx_obj = None, None, None
        while prev_tx is None:
            envelope = node.wait_for_commands([b'merkleblock', b'tx'])
            stream = envelope.stream()
            if envelope.command == b'merkleblock':
                mb = MerkleBlock.parse(stream)
                self.assertTrue(mb.is_valid())
            else:
                prev_tx_obj = Tx.parse(stream, testnet=True)
                for i, tx_out in enumerate(prev_tx_obj.tx_outs):
                    if tx_out.script_pubkey.address(testnet=True) == addr:
                        prev_tx = prev_tx_obj.hash()
                        prev_index = i
                        self.assertEqual(
                            prev_tx_obj.id(),
                            'e3930e1e566ca9b75d53b0eb9acb7607f547e1182d1d22bd4b661cfe18dcddf1')
                        self.assertEqual(i, 0)
        tx_in = TxIn(prev_tx, prev_index)
        prev_amount = prev_tx_obj.tx_outs[prev_index].amount
        output_amount = prev_amount - fee
        tx_out = TxOut(output_amount, target_script)
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        tx_obj.sign_input(0, private_key)
        self.assertEqual(tx_obj.serialize().hex(), '0100000001f1dddc18fe1c664bbd221d2d18e147f50776cb9aebb0535db7a96c561e0e93e3000000006a473044022003829abee4bff4df3d3ddf0be6f77e311a09b8e945ec33cdf103305914e84f46022043745996a4dcfd6d320378786337c320c936281218803573be66a12881c2ad350121021cdd761c7eb1c90c0af0a5963e94bf0203176b4662778d32bd6d7ab5d8628b32ffffffff01a1629ef5000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000')
