from io import BytesIO
from math import ceil, log
from unittest import TestCase

import helper
import merkleblock

from block import (
    Block,
    GENESIS_BLOCK_HASH,
    TESTNET_GENESIS_BLOCK_HASH,
)
from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from merkleblock import MerkleTree
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    NetworkEnvelope,
    SimpleNode,
    VersionMessage,
    BLOCK_DATA_TYPE,
    NETWORK_MAGIC,
    TESTNET_NETWORK_MAGIC,
)
from tx import Tx


@classmethod
def parse_ne(cls, s, testnet=False):
    magic = s.read(4)
    if magic == b'':
        raise RuntimeError('Connection reset!')
    if testnet:
        expected_magic = TESTNET_NETWORK_MAGIC
    else:
        expected_magic = NETWORK_MAGIC
    if magic != expected_magic:
        raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
    command = s.read(12)
    command = command.strip(b'\x00')
    payload_length = little_endian_to_int(s.read(4))
    checksum = s.read(4)
    payload = s.read(payload_length)
    calculated_checksum = hash256(payload)[:4]
    if calculated_checksum != checksum:
        raise RuntimeError('checksum does not match')
    return cls(command, payload, testnet=testnet)


def serialize_ne(self):
    result = self.magic
    result += self.command + b'\x00' * (12 - len(self.command))
    result += int_to_little_endian(len(self.payload), 4)
    result += hash256(self.payload)[:4]
    result += self.payload
    return result


def serialize_vm(self):
    result = int_to_little_endian(self.version, 4)
    result += int_to_little_endian(self.services, 8)
    result += int_to_little_endian(self.timestamp, 8)
    result += int_to_little_endian(self.receiver_services, 8)
    result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
    result += int_to_little_endian(self.receiver_port, 2)
    result += int_to_little_endian(self.sender_services, 8)
    result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
    result += int_to_little_endian(self.sender_port, 2)
    result += self.nonce
    result += encode_varint(len(self.user_agent))
    result += self.user_agent
    result += int_to_little_endian(self.latest_block, 4)
    if self.relay:
        result += b'\x01'
    else:
        result += b'\x00'
    return result


def serialize_gh(self):
    result = int_to_little_endian(self.version, 4)
    result += encode_varint(self.num_hashes)
    result += self.start_block[::-1]
    result += self.end_block[::-1]
    return result


@classmethod
def parse_h(cls, stream):
    num_headers = read_varint(stream)
    blocks = []
    for _ in range(num_headers):
        blocks.append(Block.parse(stream))
        num_txs = read_varint(stream)
        if num_txs != 0:
            raise RuntimeError('number of txs not 0')
    return cls(blocks)


def handshake(self):
    version = VersionMessage()
    self.send(version.command, version.serialize())
    self.wait_for_commands({b'verack'})


def merkle_parent(hash1, hash2):
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hashes):
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def validate_merkle_root(self):
    hashes = [h[::-1] for h in self.tx_hashes]
    root = merkle_root(hashes)
    return root[::-1] == self.merkle_root


class Session7Test(TestCase):

    def test_apply(self):
        NetworkEnvelope.parse = parse_ne
        NetworkEnvelope.serialize = serialize_ne
        VersionMessage.serialize = serialize_vm
        GetHeadersMessage.serialize = serialize_gh
        HeadersMessage.parse = parse_h
        SimpleNode.handshake = handshake
        helper.merkle_parent = merkle_parent
        merkleblock.merkle_parent = merkle_parent
        helper.merkle_parent_level = merkle_parent_level
        helper.merkle_root = merkle_root
        Block.validate_merkle_root = validate_merkle_root

    def test_exercise_1(self):
        msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
        command = msg[4:16]
        self.assertEqual(command, b'verack' + b'\x00' * 6)

    def test_example_1(self):
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True, logging=False)
        version = VersionMessage()
        node.send(version.command, version.serialize())
        verack = node.wait_for_commands([b'verack'])
        self.assertEqual(verack.command, b'verack')

    def test_example_2(self):
        expected = [
            '00000000693067b0e6b440bc51450b9f3850561b07f6d3c021c54fbd6abb9763',
            '00000000f037ad09d0b05ee66b8c1da83030abaf909d2b1bf519c3c7d2cd3fdf',
            '000000006ce8b5f16fcedde13acbc9641baa1c67734f177d770a4069c06c9de8',
            '00000000563298de120522b5ae17da21aaae02eee2d7fcb5be65d9224dbd601c',
            '000000009b0a4b2833b4a0aa61171ee75b8eb301ac45a18713795a72e461a946',
            '00000000fa8a7363e8f6fdc88ec55edf264c9c7b31268c26e497a4587c750584',
            '000000008ac55b5cd76a5c176f2457f0e9df5ff1c719d939f1022712b1ba2092',
            '000000007f0c796631f00f542c0b402d638d3518bc208f8c9e5d29d2f169c084',
            '00000000ffb062296c9d4eb5f87bbf905d30669d26eab6bced341bd3f1dba5fd',
            '0000000074c108842c3ec2252bba62db4050bf0dddfee3ddaa5f847076b8822f',
            '0000000067dc2f84a73fbf5d3c70678ce4a1496ef3a62c557bc79cbdd1d49f22',
            '00000000dbf06f47c0624262ecb197bccf6bdaaabc2d973708ac401ac8955acc',
            '000000009260fe30ec89ef367122f429dcc59f61735760f2b2288f2e854f04ac',
            '00000000f9f1a700898c4e0671af6efd441eaf339ba075a5c5c7b0949473c80b',
            '000000005107662c86452e7365f32f8ffdc70d8d87aa6f78630a79f7d77fbfe6',
            '00000000984f962134a7291e3693075ae03e521f0ee33378ec30a334d860034b',
            '000000005e36047e39452a7beaaa6721048ac408a3e75bb60a8b0008713653ce',
            '00000000128d789579ffbec00203a371cbb39cee27df35d951fd66e62ed59258',
            '000000008dde642fb80481bb5e1671cb04c6716de5b7f783aa3388456d5c8a85'
        ]
        node = SimpleNode('btc.programmingblockchain.com', testnet=False)
        node.handshake()
        last_block_hash = GENESIS_BLOCK_HASH
        count = 1
        for _ in range(20):
            getheaders = GetHeadersMessage(start_block=last_block_hash)
            node.send(getheaders.command, getheaders.serialize())
            headers_envelope = node.wait_for_commands([b'headers'])
            headers_message = HeadersMessage.parse(headers_envelope.stream())
            for b in headers_message.blocks:
                self.assertTrue(b.check_pow())
                if last_block_hash != GENESIS_BLOCK_HASH:
                    self.assertEqual(b.prev_block, last_block_hash)
                count += 1
                last_block_hash = b.hash()
                if count % 2016 == 0:
                    self.assertEqual(b.id(), expected.pop(0))

    def test_exercise_5(self):
        expected = [
            '00000000864b744c5025331036aa4a16e9ed1cbb362908c625272150fa059b29',
            '000000002e9ccffc999166ccf8d72129e1b2e9c754f6c90ad2f77cab0d9fb4c7',
            '0000000009b9f0436a9c733e2c9a9d9c8fe3475d383bdc1beb7bfa995f90be70',
            '000000000a9c9c79f246042b9e2819822287f2be7cd6487aecf7afab6a88bed5',
            '000000003a7002e1247b0008cba36cd46f57cd7ce56ac9d9dc5644265064df09',
            '00000000061e01e82afff6e7aaea4eb841b78cc0eed3af11f6706b14471fa9c8',
            '000000003911e011ae2459e44d4581ac69ba703fb26e1421529bd326c538f12d',
            '000000000a5984d6c73396fe40de392935f5fc2a8e48eedf38034ce0a3178a60',
            '000000000786bdc642fa54c0a791d58b732ed5676516fffaeca04492be97c243',
            '000000001359c49f9618f3ee69afbd1b3196f1832acc47557d42256fcc6b7f48',
            '00000000270dde98d582af35dff5aed02087dad8529dc5c808c67573d6dabaf4',
            '00000000425c160908c215c4adf998771a2d1c472051bc58320696f3a5eb0644',
            '0000000006a5976471986377805d4a148d8822bb7f458138c83f167d197817c9',
            '000000000318394ea17038ef369f3cccc79b3d7dfda957af6c8cd4a471ffa814',
            '000000000ad4f9d0b8e86871478cc849f7bc42fb108ebec50e4a795afc284926',
            '000000000207e63e68f2a7a4c067135883d726fd65e3620142fb9bdf50cce1f6',
            '00000000003b426d2c12ee66b2eedb4dcc05d5e158685b222240d31e43687762',
            '00000000017cf6ee86e3d483f9a978ded72be1fa5af37d287a71c5dfb87cdd83',
            '00000000004b1d9fe16fc0c72cfa0395c98a3e460cd2affb8640e28bca295a4a'
        ]
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)
        node.handshake()
        last_block_hash = TESTNET_GENESIS_BLOCK_HASH
        count = 1
        while count <= 40000:
            getheaders = GetHeadersMessage(start_block=last_block_hash)
            node.send(getheaders.command, getheaders.serialize())
            headers_envelope = node.wait_for_commands([b'headers'])
            headers_message = HeadersMessage.parse(headers_envelope.stream())
            for b in headers_message.blocks:
                self.assertTrue(b.check_pow())
                if last_block_hash != TESTNET_GENESIS_BLOCK_HASH:
                    print(count)
                    self.assertEqual(b.prev_block, last_block_hash)
                count += 1
                last_block_hash = b.hash()
                if count % 2016 == 0:
                    self.assertEqual(b.id(), expected.pop(0))

    def test_example_3(self):
        hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        parent = hash256(hash0 + hash1)
        self.assertEqual(parent.hex(), '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')

    def test_exercise_6(self):
        hex_hash0 = 'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0'
        hex_hash1 = '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181'
        hash0 = bytes.fromhex(hex_hash0)
        hash1 = bytes.fromhex(hex_hash1)
        parent = hash256(hash0 + hash1)
        self.assertEqual(parent.hex(), '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800')

    def test_example_4(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
        ]
        hashes = [bytes.fromhex(x) for x in hex_hashes]
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        parent_level = []
        for i in range(0, len(hex_hashes), 2):
            parent = merkle_parent(hashes[i], hashes[i + 1])
            parent_level.append(parent)
        want = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            '3ecf6115380c77e8aae56660f5634982ee897351ba906a6837d15ebc3a225df0',
        ]
        self.assertEqual([x.hex() for x in parent_level], want)

    def test_example_7(self):
        hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
        ]
        hashes = [bytes.fromhex(x) for x in hex_hashes]
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        parent_level = []
        for i in range(0, len(hex_hashes), 2):
            parent = merkle_parent(hashes[i], hashes[i + 1])
            parent_level.append(parent)
        want = [
            '26906cb2caeb03626102f7606ea332784281d5d20e2b4839fbb3dbb37262dbc1',
            '717a0d17538ff5ad2c020bab38bdcde66e63f3daef88f89095f344918d5d4f96',
            'd6c56a5281021a587f5a1e0dd4674bff012c69d960136d96e6d72261d5b696ae',
        ]
        self.assertEqual([x.hex() for x in parent_level], want)

    def test_example_8(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        hashes = [bytes.fromhex(x) for x in hex_hashes]
        current_level = hashes
        while len(current_level) > 1:
            current_level = merkle_parent_level(current_level)
        self.assertEqual(current_level[0].hex(), 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6')

    def test_exercise_8(self):
        hex_hashes = [
            '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
            '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
            '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
            'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
            '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
            '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
            'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
            '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
            '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
            '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
            '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
        ]
        hashes = [bytes.fromhex(x) for x in hex_hashes]
        current_level = hashes
        while len(current_level) > 1:
            current_level = merkle_parent_level(current_level)
        self.assertEqual(current_level[0].hex(), 'a67772634e542799333c6c98bc903e36b652918a8d8a9e069391c55b4276c8a1')

    def test_example_9(self):
        tx_hex_hashes = [
            '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
            '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
            '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
            'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
            '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
            '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
            'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
        ]
        tx_hashes = [bytes.fromhex(x) for x in tx_hex_hashes]
        hashes = [h[::-1] for h in tx_hashes]
        self.assertEqual(
            merkle_root(hashes)[::-1].hex(),
            '654d6181e18e4ac4368383fdc5eead11bf138f9b7ac1e15334e4411b3c4797d9')

    def test_exercise_9(self):
        want = '4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301'
        tx_hex_hashes = [
            '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
            '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
            '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
            'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
            '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
            '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
            'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
            '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
            '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
            '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
            '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
        ]
        tx_hashes = [bytes.fromhex(x) for x in tx_hex_hashes]
        hashes = [h[::-1] for h in tx_hashes]
        self.assertEqual(merkle_root(hashes)[::-1].hex(), want)

    def test_exercise_10(self):
        block_hex = '0000000000044b01a9440b34f582fe171c7b8642fedd0ebfccf8fdf6a1810900'
        block_hash = bytes.fromhex(block_hex)
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)
        node.handshake()
        getdata = GetDataMessage()
        getdata.add_data(BLOCK_DATA_TYPE, block_hash)
        node.send(getdata.command, getdata.serialize())
        block_envelope = node.wait_for_commands([b'block'])
        stream = block_envelope.stream()
        b = Block.parse(stream)
        self.assertTrue(b.check_pow())
        num_txs = read_varint(stream)
        tx_hashes = []
        for _ in range(num_txs):
            t = Tx.parse(stream)
            tx_hashes.append(t.hash())
        b.tx_hashes = tx_hashes
        self.assertTrue(b.validate_merkle_root())

    def test_example_10(self):
        total = 16
        max_depth = ceil(log(total, 2))
        merkle_tree = []
        for depth in range(max_depth + 1):
            num_items = ceil(total / 2**(max_depth - depth))
            level_hashes = [None] * num_items
            merkle_tree.append(level_hashes)
        expected = [1, 2, 4, 8, 16]
        for want, level in zip(expected, merkle_tree):
            self.assertEqual(level, [None] * want)

    def test_example_11(self):
        hex_hashes = [
            "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
            "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
            "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
            "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
            "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
            "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
            "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
            "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
            "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
            "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
            "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
            "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
            "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
            "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
            "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
            "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
        ]
        tree = MerkleTree(len(hex_hashes))
        tree.nodes[4] = [bytes.fromhex(h) for h in hex_hashes]
        tree.nodes[3] = merkle_parent_level(tree.nodes[4])
        tree.nodes[2] = merkle_parent_level(tree.nodes[3])
        tree.nodes[1] = merkle_parent_level(tree.nodes[2])
        tree.nodes[0] = merkle_parent_level(tree.nodes[1])
        self.assertEqual(tree.nodes[0][0].hex(), '597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1')

    def test_example_12(self):
        hex_hashes = [
            "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
            "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
            "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
            "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
            "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
            "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
            "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
            "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
            "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
            "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
            "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
            "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
            "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
            "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
            "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
            "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
        ]
        tree = MerkleTree(len(hex_hashes))
        tree.nodes[4] = [bytes.fromhex(h) for h in hex_hashes]
        while tree.root() is None:
            if tree.is_leaf():
                tree.up()
            else:
                left_hash = tree.get_left_node()
                right_hash = tree.get_right_node()
                if left_hash is None:
                    tree.left()
                elif right_hash is None:
                    tree.right()
                else:
                    tree.set_current_node(merkle_parent(left_hash, right_hash))
                    tree.up()
        self.assertEqual(tree.nodes[0][0].hex(), '597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1')

    def test_example_13(self):
        hex_hashes = [
            "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
            "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
            "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
            "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
            "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
            "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
            "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
            "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
            "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
            "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
            "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
            "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
            "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
            "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
            "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
            "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
            "38faf8c811988dff0a7e6080b1771c97bcc0801c64d9068cffb85e6e7aacaf51",
        ]
        tree = MerkleTree(len(hex_hashes))
        tree.nodes[5] = [bytes.fromhex(h) for h in hex_hashes]
        while tree.root() is None:
            if tree.is_leaf():
                tree.up()
            else:
                left_hash = tree.get_left_node()
                if left_hash is None:
                    tree.left()
                elif tree.right_exists():
                    right_hash = tree.get_right_node()
                    if right_hash is None:
                        tree.right()
                    else:
                        tree.set_current_node(merkle_parent(left_hash, right_hash))
                        tree.up()
                else:
                    tree.set_current_node(merkle_parent(left_hash, left_hash))
                    tree.up()
        self.assertEqual(tree.nodes[0][0].hex(), '0a313864f84b284ad13f7f93940d43459808c3c300ed274a90f265802ab10f91')
