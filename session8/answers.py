'''
#code
>>> import bloomfilter, merkleblock

#endcode
#code
>>> # Example Bloom Filter
>>> from helper import hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> h256 = hash256(b'hello world')
>>> bit = int.from_bytes(h256, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example Bloom Filter 2
>>> from helper import hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> h = hash256(b'hello world')
>>> bit = int.from_bytes(h, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> h = hash256(b'goodbye')
>>> bit = int.from_bytes(h, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 1, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example Bloom Filter 3
>>> from helper import hash160, hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> phrase1 = b'hello world'
>>> h1 = hash256(phrase1)
>>> bit1 = int.from_bytes(h1, 'big') % bit_field_size
>>> bit_field[bit1] = 1
>>> h2 = hash160(phrase1)
>>> bit2 = int.from_bytes(h2, 'big') % bit_field_size
>>> bit_field[bit2] = 1
>>> phrase2 = b'goodbye'
>>> h1 = hash256(phrase2)
>>> bit1 = int.from_bytes(h1, 'big') % bit_field_size
>>> bit_field[bit1] = 1
>>> h2 = hash160(phrase2)
>>> bit2 = int.from_bytes(h2, 'big') % bit_field_size
>>> bit_field[bit2] = 1
>>> print(bit_field)
[1, 1, 1, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example BIP0037 Bloom Filter
>>> from helper import murmur3
>>> from bloomfilter import BIP37_CONSTANT
>>> field_size = 2
>>> num_functions = 2
>>> tweak = 42
>>> bit_field_size = field_size * 8
>>> bit_field = [0] * bit_field_size
>>> for phrase in (b'hello world', b'goodbye'):
...     for i in range(num_functions):
...         seed = i * BIP37_CONSTANT + tweak
...         h = murmur3(phrase, seed=seed)
...         bit = h % bit_field_size
...         bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0]

#endcode
#exercise
Given a Bloom Filter with these parameters: size=10, function count=5, tweak=99, which bits are set after adding these items? 

 * `b'Hello World'`
 * `b'Goodbye!'`
---
>>> from bloomfilter import BIP37_CONSTANT
>>> from helper import murmur3, bit_field_to_bytes
>>> field_size = 10
>>> function_count = 5
>>> tweak = 99
>>> items = (b'Hello World',  b'Goodbye!')
>>> # bit_field_size is 8 * field_size
>>> bit_field_size = field_size * 8  #/
>>> # create a bit field with the appropriate size
>>> bit_field = [0] * bit_field_size  #/
>>> # for each item you want to add to the filter
>>> for item in items:  #/
...     # iterate function_count number of times
...     for i in range(function_count):  #/
...         # BIP0037 spec seed is i*BIP37_CONSTANT + tweak
...         seed = i * BIP37_CONSTANT + tweak  #/
...         # get the murmur3 hash given that seed
...         h = murmur3(item, seed=seed)  #/
...         # set the bit to be h mod the bit_field_size
...         bit = h % bit_field_size  #/
...         # set the bit_field at the index bit to be 1
...         bit_field[bit] = 1  #/
>>> # print the bit field converted to bytes using bit_field_to_bytes in hex
>>> print(bit_field_to_bytes(bit_field).hex())  #/
4000600a080000010940

#endexercise
#unittest
bloomfilter:BloomFilterTest:test_add:
#endunittest
#unittest
bloomfilter:BloomFilterTest:test_filterload:
#endunittest
#exercise
Do the following:

* Connect to a testnet node
* Load a filter for your testnet address
* Send a request for transactions from the block which had your previous testnet transaction
* Receive the merkleblock and tx messages.
---
>>> from bloomfilter import BloomFilter
>>> from ecc import PrivateKey
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from merkleblock import MerkleBlock
>>> from network import SimpleNode, GetDataMessage, FILTERED_BLOCK_DATA_TYPE
>>> from tx import Tx
>>> block_hash = bytes.fromhex('00000000000377db7fde98411876c53e318a395af7304de298fd47b7c549d125')  #/block_hash = bytes.fromhex('<block hash from class>')  # CHANGE
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(testnet=True)
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> filter_size = 30
>>> filter_num_functions = 5
>>> filter_tweak = 90210  #/filter_tweak = -1  # CHANGE
>>> # get the hash160 of the address using decode_base58
>>> h160 = decode_base58(addr)  #/
>>> # create a bloom filter using the filter_size, filter_num_functions and filter_tweak above
>>> bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)  #/
>>> # add the h160 to the bloom filter
>>> bf.add(h160)  #/
>>> # connect to tbtc.programmingblockchain.com in testnet mode
>>> node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # send the filterload message
>>> node.send(bf.filterload())  #/
>>> # create a getdata message
>>> getdata = GetDataMessage()  #/
>>> # add_data (FILTERED_BLOCK_DATA_TYPE, block_hash) to request the block
>>> getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the getdata message
>>> node.send(getdata)  #/
>>> # wait for the merkleblock command
>>> mb = node.wait_for(MerkleBlock)  #/
>>> # wait for the tx command
>>> tx_obj = node.wait_for(Tx)  #/
>>> # print the envelope payload in hex
>>> print(tx_obj.serialize().hex())  #/
01000000013fdfef60ecd21c5e667cfe30fcb890a116688ca51ac3880f91008dd141ddcdb2080000006b483045022100b0453c379054fe909ce09d6a37eba3b8fc1fc4b7dcbe34e6a21125a513189ab402200ccefbb93951f881c93b195ae5f0d93c14aa1eda9680274bc0169f2089f778c20121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6effffffff0280969800000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ace19c5a81000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000

#endexercise
#unittest
merkleblock:MerkleBlockTest:test_is_valid:
#endunittest
#exercise
You have been sent some unknown amount of testnet bitcoins to your address. 

Send all of it back (minus fees) to `mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv` using only the networking protocol.

This should be a 1 input, 1 output transaction.

Remember turn on logging in `SimpleNode` if you need to debug
---
>>> from time import sleep
>>> from block import Block
>>> from bloomfilter import BloomFilter, BIP37_CONSTANT
>>> from ecc import PrivateKey
>>> from helper import bit_field_to_bytes, decode_base58, hash160, hash256, little_endian_to_int, murmur3, SIGHASH_ALL
>>> from merkleblock import MerkleBlock
>>> from network import GetDataMessage, GetHeadersMessage, HeadersMessage, SimpleNode, FILTERED_BLOCK_DATA_TYPE, TX_DATA_TYPE
>>> from script import p2pkh_script
>>> from tx import Tx, TxIn, TxOut
>>> last_block_hex = '00000000000377db7fde98411876c53e318a395af7304de298fd47b7c549d125'  #/last_block_hex = '<block hash from class>'  # CHANGE
>>> last_block = bytes.fromhex(last_block_hex)
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(testnet=True)
>>> h160 = decode_base58(addr)
>>> target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
>>> filter_size = 30
>>> filter_num_functions = 5
>>> filter_tweak = 90210  #/filter_tweak = -1  # CHANGE
>>> target_h160 = decode_base58(target_address)
>>> target_script = p2pkh_script(target_h160)
>>> fee = 5000  # fee in satoshis
>>> # connect to tbtc.programmingblockchain.com in testnet mode, logging True
>>> node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)  #/
>>> # create a bloom filter using variables above
>>> bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)  #/
>>> # add the h160 to the bloom filter
>>> bf.add(h160)  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # send the 'filterload' message
>>> node.send(bf.filterload())  #/
>>> # create GetHeadersMessage with the last_block as the start_block
>>> getheaders = GetHeadersMessage(start_block=last_block)  #/
>>> # send a getheaders message
>>> node.send(getheaders)  #/
>>> # wait for the headers message
>>> headers = node.wait_for(HeadersMessage)  #/
>>> # initialize the GetDataMessage
>>> getdata = GetDataMessage()  #/
>>> # loop through the headers in the headers message
>>> for header in headers.headers:  #/
...     # check that the proof of work on the block is valid
...     if not header.check_pow():  #/
...         raise RuntimeError  #/
...     # check that this block's prev_block is the last block
...     if last_block is not None and header.prev_block != last_block:  #/
...         raise RuntimeError  #/
...     # set the last block to the current hash
...     last_block = header.hash()  #/
...     # add_data(FILTERED_BLOCK_DATA_TYPE, last_block) to get_data_message
...     getdata.add_data(FILTERED_BLOCK_DATA_TYPE, last_block)  #/
>>> # send the getdata message
>>> node.send(getdata)  #/
>>> # initialize prev_tx to None
>>> prev_tx = None  #/
>>> # while prev_tx is None 
>>> while prev_tx is None:  #/
...     # wait for the merkleblock or tx commands
...     message = node.wait_for(MerkleBlock, Tx)  #/
...     # if we have the merkleblock command
...     if message.command == b'merkleblock':  #/
...         # check that the MerkleBlock is valid
...         if not message.is_valid():  #/
...             raise RuntimeError  #/
...     # else we have the tx command
...     else:  #/
...         # set message.testnet=True
...         message.testnet = True  #/
...         # loop through the enumerated tx outs (enumerate(message.tx_outs))
...         for i, tx_out in enumerate(message.tx_outs):  #/
...             # if our output has the same address as our address (addr) we found it
...             if tx_out.script_pubkey.address(testnet=True) == addr:  #/
...                 # we found our utxo. set prev_tx, prev_index, prev_amount
...                 prev_tx = message.hash()  #/
...                 prev_index = i  #/
...                 prev_amount = tx_out.amount  #/
...                 # break
...                 break  #/
>>> # create tx_in
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the output amount (prev_amount - fee)
>>> output_amount = prev_amount - fee  #/
>>> # create tx_out
>>> tx_out = TxOut(output_amount, target_script)  #/
>>> # create transaction on testnet
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)  #/
>>> # sign the one input we have
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> # serialize and hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
0100000001c2d4d9c372e8e24adb77236d33de2126b2cf80c3b1199e4706a652d5814c392c000000006a47304402205b90755998b0a16b51c0168c471eb126381a28bf51eccc661918e7cffdb8110202206a1887fb3c197f003eb1ce1fbf203c80820050b73cebc02f60fb08d82b1fb66d012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff01cc80a100000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000
>>> # send this signed transaction on the network
>>> node.send(tx_obj)  #/
>>> # wait a sec so this message goes through to the other node sleep(1) 
>>> sleep(1)  #/
>>> # now ask for this transaction from the other node
>>> # create a GetDataMessage
>>> getdata = GetDataMessage()  #/
>>> # add_data (TX_DATA_TYPE, tx_obj.hash()) to get data message
>>> getdata.add_data(TX_DATA_TYPE, tx_obj.hash())  #/
>>> # send the GetDataMessage
>>> node.send(getdata)  #/
>>> # now wait for a response
>>> got = node.wait_for(Tx)  #/
>>> if got.id() == tx_obj.id():  #/
...     # yes! we got to what we wanted
...     print('success!')  #/
...     print(tx_obj.id())  #/
success!
d3c1913e778a451759db4df9c8c55b2575c855608271c5044b26ebcd02791564

#endexercise
'''


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
    GenericMessage,
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
    return GenericMessage(b'filterload', payload)


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


if __name__ == "__main__":
    import doctest
    doctest.testmod()
