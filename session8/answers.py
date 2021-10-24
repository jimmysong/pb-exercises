'''
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
>>> block_hash = bytes.fromhex('00000000000000025d631a0e2d198b3e6904b988c3c37832270f547c5b7f0b4e')  #/block_hash = bytes.fromhex('<block hash from class>')  # CHANGE
>>> block_height = 1976197  #/block_height = -1  # CHANGE
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(testnet=True)
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> # convert the address to a ScriptPubKey using decode_base58 and p2pkh_script
>>> script_pubkey = p2pkh_script(decode_base58(addr))  #/
>>> # connect to testnet.programmingbitcoin.com in testnet mode
>>> node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # create a GetCFiltersMessage using the block height and block hash
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
>>> # use the get_transactions method of Block to get transactions
>>> txs = b.get_transactions(script_pubkey)  #/
>>> # print the first one serialized and hexadecimal
>>> print(txs[0].serialize().hex())  #/
0100000001f7cca7a7fbc0a4872661643bbadd7a0d5e2ba62c064fd3fdb80f863285ecc3ee000000006a473044022073561bdf6ab8e5993435637f83859d7b744a10e86e323bcaeb7bfe7a9b6e87140220145989b8a6bcc8aaca79e729c8d7157ea7d3358e7d9ad0384a38bc30a0c9db9a012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff0200093d00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac07868200000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ac00000000

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
>>> node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)
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
You have been sent some unknown amount of testnet bitcoins to your address.

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
>>> start_block_hex = '000000008d4459b8110998b565b736360f58355199ca120b9e5fa02f05a71c93'  #/ start_block_hex = '<insert from class>'  # CHANGE
>>> start_block = bytes.fromhex(start_block_hex)
>>> start_height = 1486230  #/ start_height = -1  # CHANGE
>>> end_block = b'\x00' * 32
>>> passphrase = b'Jimmy Song'  #/ passphrase = b'<get from session 2>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(testnet=True)
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> h160 = decode_base58(addr)
>>> my_script_pubkey = p2pkh_script(h160)
>>> target_address = 'mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv'
>>> target_h160 = decode_base58(target_address)
>>> target_script = p2pkh_script(target_h160)
>>> fee = 5000  # fee in satoshis
>>> # connect to testnet.programmingbitcoin.com in testnet mode
>>> node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)  #/
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
>>> # get the 99th hash from the header.headers array
>>> stop_hash = headers.headers[99].hash()  #/
>>> # create a GetCFiltersMessage
>>> get_cfilters = GetCFiltersMessage(start_height=start_height, stop_hash=stop_hash)  #/
>>> # send the GetCFiltersMessage
>>> node.send(get_cfilters)  #/
>>> # initialize the block_hashes array
>>> block_hashes = []  #/
>>> # loop 100 times
>>> for _ in range(100):  #/
...     # wait for the CFilterMessage
...     cfilter = node.wait_for(CFilterMessage)  #/
...     # check to see if your ScriptPubKey is in the filter
...     if my_script_pubkey in cfilter:  #/
...         # add cfilter's block hash to the hashes we need to go get
...         block_hashes.append(cfilter.block_hash)  #/
...         print(cfilter.block_hash.hex())  #/
000000001044cfa9a8a4716548cddb324448ef11b495561313b9495d0051bdad
>>> # create a GetDataMessage
>>> get_data = GetDataMessage()  #/
>>> # add_data to the GetDataMessage for each block hash
>>> for block_hash in block_hashes:  #/
...     get_data.add_data(BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the GetDataMessage
>>> node.send(get_data)  #/
>>> # initialize the utxos array
>>> utxos = []  #/
>>> # for every block hash, wait for a block message
>>> for block_hash in block_hashes:  #/
...     b = node.wait_for(Block)  #/
...     # check that the hashes match for the block
...     if b.hash() != block_hash:  #/
...         raise RuntimeError('bad block')  #/
...     # loop through the transactions corresponding to our ScriptPubKey using the get_transactions method
...     for tx_obj in b.get_transactions(my_script_pubkey):  #/
...         # use find_utxos to get utxos that belong to our address
...         new_utxos = tx_obj.find_utxos(addr)  #/
...         # add to the utxos array using extend method
...         utxos.extend(new_utxos)  #/
>>> # initialize the input sum
>>> input_sum = 0  #/
>>> # initialize the tx_ins array
>>> tx_ins = []  #/
>>> # for each utxo, create a TxIn
>>> for utxo in utxos:  #/
...     # prev_tx, prev_index, prev_amount are what we get in each utxo
...     prev_tx, prev_index, prev_amount = utxo  #/
...     # create TxIn and add to array
...     tx_ins.append(TxIn(prev_tx, prev_index))  #/
...     # add the amount to the input sum
...     input_sum += prev_amount  #/
>>> # calculate the output amount (input_sum - fee)
>>> output_amount = prev_amount - fee  #/
>>> # create tx_out
>>> tx_out = TxOut(output_amount, target_script)  #/
>>> # create transaction on testnet
>>> tx_obj = Tx(1, tx_ins, [tx_out], 0, testnet=True)  #/
>>> # sign the inputs we have
>>> for i in range(len(tx_ins)):  #/
...     tx_obj.sign_input(i, private_key)  #/
>>> # serialize and hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
01000000022f4253b1f1ff81a38fbf88424bc4795d0c6d493d30db91265249951beee83e86110000006b483045022100e0c8db514f9a8433930a742295be139208340a27a26dcb3c84bcadce034287150220661f37de000512e663e20b923e53fd6c4b1fed1271deb94da71a669f72e17220012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff45d4df59c7d9b50d73616f509ddfdcc13bd3ad03655bef04056ea969ae15ab260000000000ffffffff01f8829800000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000
>>> # send this signed transaction on the network
>>> node.send(tx_obj)  #/

#endexercise
'''


from unittest import TestCase

from network import (
    GetDataMessage,
    SimpleNode,
    BLOCK_DATA_TYPE,
)


def get_block(self, block_hash):
    getdata = GetDataMessage()
    getdata.add_data(BLOCK_DATA_TYPE, block_hash)
    self.send(getdata)
    return self.wait_for(Block)


class Session8Test(TestCase):

    def test_apply(self):
        SimpleNode.get_block = get_block


if __name__ == "__main__":
    import doctest
    doctest.testmod()
