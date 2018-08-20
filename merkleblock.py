import math

from io import BytesIO
from unittest import TestCase

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_parent,
    merkle_parent_level,
    merkle_path,
    merkle_root,
    read_varint,
    encode_varint,
)


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
        self.max_depth = math.ceil(math.log(self.total, 2))

    def __repr__(self):
        print(self.total)
        for h in self.hashes:
            print(h.hex())
        print(self.flags.hex())
        
    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''
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
        # total number of transactions
        total = little_endian_to_int(s.read(4))
        # number of transactions in this merkle proof
        num_txs = read_varint(s)
        # hashes of these transactions
        hashes = []
        for _ in range(num_txs):
            hashes.append(s.read(32)[::-1])
        flags_size = read_varint(s)
        flags = s.read(flags_size)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce,
                   total, hashes, flags)

    def compute_root(self):
        # compute the flag bits
        self.flag_bits = []
        # iterate over each byte of flags
        for byte in self.flags:
            # iterate over each bit, right-to-left
            for _ in range(8):
                self.flag_bits.append(byte & 1)
                byte >>= 1
        # hashes to be consumed
        self.tmp_hashes = [h[::-1] for h in self.hashes]
        # return the computed merkle root, which should be at depth 0 index 0
        return self.get_hash(0, 0)[::-1]

    def get_hash(self, depth, index):
        # we need to get the hash at a certain depth and index
        # grab the bit associated with this node in the merkle tree
        current_bit = self.flag_bits.pop(0)
        if current_bit == 0:
            # if the bit is 0, the next hash on the list is this current hash
            return self.tmp_hashes.pop(0)
        elif depth == self.max_depth:
            # similarly, if we are a leaf node (that is, at the max depth)
            # the next hash on the list is the current hash
            return self.tmp_hashes.pop(0)
        else:
            # we are an internal node or something on the merkle path
            # we need to compute this node's hash by calculating the two
            # child node hashes
            # the left child's index is double the current node's
            left_index = index * 2
            # the right child index is one more than the left one
            right_index = left_index + 1
            # the left one can be computed using recursion with a depth + 1
            left = self.get_hash(depth+1, left_index)
            # the right one may or may not exist
            # we have to determine the maximum index at this level
            # and that's given by this formula:
            # math.ceil(self.total / 2**(self.max_depth - depth - 1))
            max_index = math.ceil(self.total / 2**(self.max_depth - depth - 1))
            if right_index > max_index:
                # if the right index is bigger than the max, we can compute
                # this node's hash by using the left one twice
                return merkle_parent(left, left)
            else:
                # otherwise, we need to also get the right hash to calculate
                # this node's hash
                right = self.get_hash(depth+1, right_index)
                return merkle_parent(left, right)

    def is_valid(self):
        # check if the computed root is the same as the merkle root
        return self.compute_root() == self.merkle_root


class MerkleBlockTest(TestCase):

    def test_compute_root(self):
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

        mb = MerkleBlock(0,0,0,0,0,0, 1833, hashes, bytes.fromhex('5d7505'))
        self.assertEqual(
            mb.compute_root().hex(),
            '3737a795b537b2dbeeb0c07a2253cc4b0da8174aabb4f9e55d59d61ede3abf4d')
        self.assertEqual(mb.tmp_hashes, [])
        for bit in mb.flag_bits:
            self.assertEqual(bit, 0)
