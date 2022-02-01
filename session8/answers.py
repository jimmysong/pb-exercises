"""
#code
>>> import network, compactfilter

#endcode
#exercise
Verify that the block which had your previous transaction matches the filter for your address.
---
>>> from block import Block
>>> from compactfilter import GetCFiltersMessage, CFilterMessage
>>> from ecc import PrivateKey
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from network import SimpleNode, GetDataMessage, BLOCK_DATA_TYPE
>>> from script import p2pkh_script
>>> from tx import Tx
>>> block_hash = bytes.fromhex('00000006439f526ce138524262a29500258db39130e1ddf0c168ca59002877b8')  #/block_hash = bytes.fromhex('<block hash from class>')  # CHANGE
>>> block_height = 75912  #/block_height = -1  # CHANGE
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(network="signet")
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> # convert the address to a ScriptPubKey using decode_base58 and p2pkh_script
>>> script_pubkey = p2pkh_script(decode_base58(addr))  #/
>>> # connect to signet.programmingbitcoin.com
>>> node = SimpleNode('signet.programmingbitcoin.com', network="signet")  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # create a GetCFiltersMessage(start_height, stop_hash) using the block height and block hash
>>> getcfilters = GetCFiltersMessage(start_height=block_height, stop_hash=block_hash)  #/
>>> # send the getcfilters message
>>> node.send(getcfilters)  #/
>>> # wait for the CFilterMessage command
>>> cfilter = node.wait_for(CFilterMessage)  #/
>>> # check that the compact filter's block hash is the same as the block hash
>>> if cfilter.block_hash != block_hash:  #/
...     raise RuntimeError('Wrong Compact Filter')  #/
>>> # check if your ScriptPubKey is in the filter
>>> if not script_pubkey in cfilter:  #/
...     raise RuntimeError('ScriptPubKey not in filter')  #/
>>> # create a GetDataMessage
>>> getdata = GetDataMessage()  #/
>>> # add the BLOCK_DATA_TYPE with the block hash
>>> getdata.add_data(BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the GetDataMessage
>>> node.send(getdata)  #/
>>> # wait for the Block
>>> b = node.wait_for(Block)  #/
>>> # use the get_transactions(script_pubkey) method of Block to get transactions
>>> txs = b.get_transactions(script_pubkey)  #/
>>> # print the first one serialized and hexadecimal
>>> print(txs[0].serialize().hex())  #/
0100000001ff5cf6387deac5a25e72ebb753d6adfa487fbac4d5996731213349546a96ae950100000000ffffffff02a0860100000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ac43f54e5202000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721400000000

#endexercise
#unittest
network:SimpleNodeTest:test_get_block:
#endunittest
#code
>>> from block import Block
>>> from compactfilter import GetCFCheckPointMessage, CFCheckPointMessage, GetCFHeadersMessage, CFHeadersMessage, GetCFiltersMessage, CFilterMessage
>>> from helper import hash256
>>> from network import SimpleNode
>>> num_checkpoints = 20
>>> with open('block_headers.testnet', 'rb') as f:
...     headers = [Block.parse_header(f) for _ in range(num_checkpoints * 1000)]
>>> block_hashes = [b.hash() for b in headers]
>>> node = SimpleNode('testnet.programmingbitcoin.com', network="testnet")
>>> node.handshake()
>>> get_cfcheckpoint = GetCFCheckPointMessage(stop_hash=block_hashes[-1])
>>> node.send(get_cfcheckpoint)
>>> cfcheckpoint = node.wait_for(CFCheckPointMessage)
>>> height = 0
>>> for checkpoint in cfcheckpoint.filter_headers:
...     get_cfheaders = GetCFHeadersMessage(start_height=height, stop_hash=block_hashes[height+1000])
...     node.send(get_cfheaders)
...     cfheaders = node.wait_for(CFHeadersMessage)
...     if cfheaders.last_header != checkpoint:
...         raise RuntimeError(f'checkpoint mismatch {cfheaders.last_header.hex()} vs {checkpoint.hex()}')
...     node.send(GetCFiltersMessage(start_height=height, stop_hash=block_hashes[height+999]))
...     for i in range(1000):
...         fb = node.wait_for(CFilterMessage).filter_bytes
...         if hash256(fb) != cfheaders.filter_hashes[i]:
...             raise RuntimeError(f'{i}: filter does not match hash {hash256(fb).hex()} vs {cfheaders.filter_hashes[i].hex()}')
...     height += 1000
>>> print(cfheaders.last_header.hex())
1a85880987940c0eb4803aa30397e9f086e09c54e283ce6bbd9d646dcedbb116

#endcode
#exercise
You have been sent some unknown number of sats to your address on signet.

Send all of it back (minus fees) to `mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv` using only the networking protocol.

This should be a many input, 1 output transaction.

Turn on logging in `SimpleNode` if you need to debug
---
>>> from block import Block
>>> from compactfilter import GetCFiltersMessage, CFilterMessage
>>> from ecc import PrivateKey
>>> from helper import decode_base58, hash160, hash256, little_endian_to_int
>>> from network import GetHeadersMessage, HeadersMessage, SimpleNode, BLOCK_DATA_TYPE
>>> from script import p2pkh_script
>>> from tx import Tx, TxIn, TxOut
>>> start_block_hex = '00000031144d96f3d297c17b092c7bed5acd3d027e37dd4a866f3313614bd4ca'  #/start_block_hex = '<insert from class>'  # CHANGE
>>> start_block = bytes.fromhex(start_block_hex)
>>> start_height = 76218  #/start_height = -1  # CHANGE
>>> end_block = b'\x00' * 32
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<get from session 2>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(network="signet")
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> h160 = decode_base58(addr)
>>> my_script_pubkey = p2pkh_script(h160)
>>> target_address = 'mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv'
>>> target_h160 = decode_base58(target_address)
>>> target_script = p2pkh_script(target_h160)
>>> fee = 200  # fee in satoshis
>>> # connect to signet.programmingbitcoin.com in signet mode
>>> node = SimpleNode('signet.programmingbitcoin.com', network="signet")  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # create GetHeadersMessage with the start_block as the start_block and end_block as the end block
>>> get_headers = GetHeadersMessage(start_block=start_block, end_block=end_block)  #/
>>> # send the GetHeadersMessage
>>> node.send(get_headers)  #/
>>> # wait for the headers message
>>> headers = node.wait_for(HeadersMessage)  #/
>>> # check that the headers are valid
>>> if not headers.is_valid():  #/
...     raise RuntimeError('bad headers')  #/
>>> # get the 20th hash (index 19) from the header.headers array
>>> stop_hash = headers.headers[19].hash()  #/
>>> # create a GetCFiltersMessage
>>> get_cfilters = GetCFiltersMessage(start_height=start_height, stop_hash=stop_hash)  #/
>>> # send the GetCFiltersMessage
>>> node.send(get_cfilters)  #/
>>> # loop 100 times
>>> for _ in range(100):  #/
...     # wait for the CFilterMessage
...     cfilter = node.wait_for(CFilterMessage)  #/
...     # check to see if your ScriptPubKey is in the filter
...     if my_script_pubkey in cfilter:  #/
...         # set block_hash to cfilter's block hash and break
...         block_hash = cfilter.block_hash  #/
...         print(block_hash.hex())  #/
...         break
0000013cacd6f0e096f8c059241f389211fc014bf7134ed0b83298788a86c9ad
>>> # get the block object using the get_block method of node
>>> block_obj = node.get_block(block_hash)  #/
>>> # initialize the utxos array
>>> utxos = []  #/
>>> # grab the txs from the block using get_transactions(my_script_pubkey) method
>>> txs = block_obj.get_transactions(my_script_pubkey)  #/
>>> # there should be one transaction
>>> if len(txs) != 1:
...     raise RuntimeError("incorrect number of transactions")
>>> # set utxos to the tx's utxos for our address using find_utxos(addr) method of the first tx
>>> utxos = txs[0].find_utxos(addr)  #/
>>> # there should be one utxo
>>> if len(utxos) != 1:
...     raise RuntimeError("incorrect number of utxos")
>>> # initialize the tx_ins array
>>> tx_ins = []  #/
>>> # prev_tx, prev_index, prev_amount are what we get in the first utxo
>>> prev_tx, prev_index, prev_amount = utxos[0]  #/
>>> # create TxIn and add to array
>>> tx_ins.append(TxIn(prev_tx, prev_index))  #/
>>> # calculate the output amount (prev_amount - fee)
>>> output_amount = prev_amount - fee  #/
>>> # create TxOut
>>> tx_out = TxOut(output_amount, target_script)  #/
>>> # create transaction on signet
>>> tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet")  #/
>>> # sign the only input in the tx
>>> tx_obj.sign_input(0, private_key)  #/
>>> # print the tx's id
>>> print(tx_obj.id())  #/
010000000181b0ad7cc5c3c09cee885623770e11bf75b8ba6b116200899232ada028ee0ced000000006a473044022028b72508fff22703396a78b4428ec64ad98c598ca4ac9c0d7da1f4a51442afd6022049bc6580793eb6ba15058bccbada80175547d558b74375e7dc4b2e3de54a0e00012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff01e1c70000000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000
>>> # send this signed transaction on the network
>>> node.send(tx_obj)  #/

#endexercise
"""


from unittest import TestCase

from block import Block
from network import (
    GetDataMessage,
    SimpleNode,
    BLOCK_DATA_TYPE,
)


def get_block(self, block_hash):
    getdata = GetDataMessage()
    getdata.add_data(BLOCK_DATA_TYPE, block_hash)
    self.send(getdata)
    block_obj = self.wait_for(Block)
    if block_obj.hash() != block_hash:
        raise RuntimeError("Got the wrong block")
    return block_obj


class Session8Test(TestCase):
    def test_apply(self):
        SimpleNode.get_block = get_block


if __name__ == "__main__":
    import doctest

    doctest.testmod()
