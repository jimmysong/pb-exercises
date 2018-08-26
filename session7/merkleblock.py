import math

from io import BytesIO
from unittest import TestCase

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_parent,
    merkle_parent_level,
    merkle_root,
    read_varint,
    encode_varint,
)


class MerkleTree:

    def __init__(self, total):
        self.total = total
        # compute max depth math.ceil(math.log(self.total, 2))
        # initialize the nodes property to hold the actual tree
        # loop over the number of levels (max_depth+1)
            # the number of items at this depth is
            # math.ceil(self.total / 2**(self.max_depth - depth))
            # create this level's hashes list with the right number of items
            # append this level's hashes to the merkle tree
        # set the pointer to the root (depth=0, index=0)
        self.current_depth = 0
        self.current_index = 0
        
    def __repr__(self):
        result = ''
        for depth, level in enumerate(self.nodes):
            for index, h in enumerate(level):
                short = '{}...'.format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    result += '*{}*, '.format(short[:-2])
                else:
                    result += '{}, '.format(short)
            result += '\n'
        return result

    def up(self):
        # reduce depth by 1 and halve the index
        self.current_depth -= 1
        self.current_index //= 2
        
    def left(self):
        # increase depth by 1 and double the index
        self.current_depth += 1
        self.current_index *= 2
        
    def right(self):
        # increase depth by 1 and double the index + 1
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]
    
    def get_left_node(self):
        return self.nodes[self.current_depth+1][self.current_index*2]        

    def get_right_node(self):
        return self.nodes[self.current_depth+1][self.current_index*2+1]
    
    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1
    
    def populate_tree(self, flag_bits, hashes):
        # populate until we have the root
            # if we are a leaf, we know this position's hash
                # get the next bit from flag_bits: flag_bits.pop(0)
                # set the current node in the merkle tree to the next hash: hashes.pop(0)
                # go up a level
            # else
                # get the left hash
                # Exercise 6.2: get the right hash
                # if we don't have the left hash
                    # if the next flag bit is 0, the next hash is our current node
                        # set the current node to be the next hash
                        # sub-tree doesn't need calculation, go up
                    # else
                        # go to the left node
                # Exercise 6.2: if we don't have the right hash
                    # go to the right node
                # Exercise 6.2: else
                    # combine the left and right hashes
                    # we've completed this subtree, go up
                # Exercise 7.2: if the right hash exists
                    # get the right hash
                    # if we don't have the right hash
                        # go to the right node
                    # else
                        # combine the left and right hashes
                        # we've completed this sub-tree, go up
                # Exercise 7.2: if the right hash doesn't exist
                    # combine the left hash twice
                    # we've completed this sub-tree, go up
        if len(hashes) != 0:
            raise RuntimeError('hashes not all consumed {}'.format(len(hashes)))
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError('flag bits not all consumed')
                

class MerkleTreeTest(TestCase):
    
    def test_init(self):
        tree = MerkleTree(9)
        self.assertEqual(len(tree.nodes[0]), 1)
        self.assertEqual(len(tree.nodes[1]), 2)
        self.assertEqual(len(tree.nodes[2]), 3)
        self.assertEqual(len(tree.nodes[3]), 5)
        self.assertEqual(len(tree.nodes[4]), 9)
        
    def test_populate_tree_1(self):
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
        hashes = [bytes.fromhex(h) for h in hex_hashes]
        tree.populate_tree([1] * 31, hashes)
        root = '597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1'
        self.assertEqual(tree.root().hex(), root)

    def test_populate_tree_2(self):
        hex_hashes = [
            '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
            '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
            '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
            'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
            '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
        ]
        tree = MerkleTree(len(hex_hashes))
        hashes = [bytes.fromhex(h) for h in hex_hashes]
        tree.populate_tree([1] * 11, hashes)
        root = 'a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab'
        self.assertEqual(tree.root().hex(), root)


class MerkleBlock:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.total = total
        self.hashes = hashes
        self.flags = flags

    def __repr__(self):
        result = '{}\n'.format(self.total)
        for h in self.hashes:
            result += '\t{}\n'.format(h.hex())
        result += '{}'.format(self.flags.hex())
        
    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a merkle block. Returns a Merkle Block object'''
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
        # total number of transactions (4 bytes, little endian)
        total = little_endian_to_int(s.read(4))
        # number of transactions in this merkle proof (varint)
        num_txs = read_varint(s)
        # hashes of these transactions
        hashes = []
        for _ in range(num_txs):
            # hashes are 32 bytes, little endian
            hashes.append(s.read(32)[::-1])
        # length of flags field is a varint
        flags_length = read_varint(s)
        # read the flags field
        flags = s.read(flags_length)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce,
                   total, hashes, flags)

    def flag_bits(self):
        flag_bits = []
        # iterate over each byte of flags
        for byte in self.flags:
            # iterate over each bit, right-to-left
            for _ in range(8):
                # add the current bit (byte & 1)
                flag_bits.append(byte & 1)
                # rightshift the byte 1
                byte >>= 1
        return flag_bits
        
    def compute_root(self):
        # initialize the flag bits
        flag_bits = self.flag_bits()
        # reverse the hashes to get our list of hashes for merkle root calculation
        hashes = [h[::-1] for h in self.hashes]
        # initialize the merkle tree
        merkle_tree = MerkleTree(self.total)
        # populate the tree with flag bits and hashes
        merkle_tree.populate_tree(flag_bits, hashes)
        # return the reversed root
        return merkle_tree.root()[::-1]

    def is_valid(self):
        # check if the computed root is the same as the merkle root
        return self.compute_root() == self.merkle_root


class MerkleBlockTest(TestCase):

    def test_is_valid(self):
        hex_hashes = [
            '588435cd03b7e16949376739849cd0becf45e8b348d7e4f3dbf0a33cb29d9796',
            'fe82bf2b781279df33995d73dc18a911e3a80b5d4af164733bbb7f8a2d11f0c9',
            'c3d254cc9fa61966ba6909ef47f0b5b4abfb02fa6afd63579de909f482e86c6e',
            '99863ea996243858ef4db44323f1b4edc5a0baef0a535bf3280b278b24c297c7',
            'e971383696bdc46be3be122329ea7e7c50396f6ff32bffab45a8a16ebebdb446',
            'b6bf15578d91377b184edfbe1404cf763c8d225a116a0447dd00eb68125f5b5a',
            'd664f9d31248b2e1110519e4997ee2ad21f743140dc0d9a795c5aeba699f0b8a',
            '1926ebd39ea4ac13c3b54e9c9eb50e5daaa738164ed495b7a208c3b95c6f3dd0',
            '4f972e4fbf1df829793a3fa0539d9d6040adc9eb34eb64c2cfc8e3dfad35e049',
            'db2780ceed2f0fc0d6ae4231e3258b22c837d0c3ee991b9c269b6d372a5eba15',
            '742d0959afcc65c8912a216d9e45c10f9a8d1530ebe7ea5d86edb67342d7fa30',
            '3c0372a0a5d428de0e8604b9aa36f88431bc7a94315ef9a1f2fc127824dd091d'
        ]
        hashes = [bytes.fromhex(h) for h in hex_hashes]
        merkle_root_hex = '3737a795b537b2dbeeb0c07a2253cc4b0da8174aabb4f9e55d59d61ede3abf4d'
        merkle_root = bytes.fromhex(merkle_root_hex)
        flag_bits = bytes.fromhex('5d7505')
        mb = MerkleBlock(0,0,merkle_root,0,0,0, 1833, hashes, flag_bits)
        self.assertTrue(mb.is_valid())
#        relevant_tx_hex = '1926ebd39ea4ac13c3b54e9c9eb50e5daaa738164ed495b7a208c3b95c6f3dd0'
#        self.assertEqual(mb.relevant_tx_hashes, [bytes.fromhex(relevant_tx_hex)])
