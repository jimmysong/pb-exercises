"""
#code
>>> import network, block

#endcode
#unittest
block:BlockTest:test_get_transactions:
#endunittest
#exercise
Check that the block with your previous transaction in fact has it
---
>>> from block import Block
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
>>> # create a GetDataMessage
>>> getdata = GetDataMessage()  #/
>>> # add the BLOCK_DATA_TYPE with the block hash
>>> getdata.add_data(BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the GetDataMessage
>>> node.send(getdata)  #/
>>> # wait for the Block
>>> b = node.wait_for(Block)  #/
>>> # get transactions in this block that have your ScriptPubKey
>>> txs = b.get_transactions(script_pubkey)  #/
>>> # print the first one serialized and hexadecimal
>>> print(txs[0].serialize().hex())  #/
0100000001ff5cf6387deac5a25e72ebb753d6adfa487fbac4d5996731213349546a96ae950100000000ffffffff02a0860100000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ac43f54e5202000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721400000000

#endexercise
#unittest
network:SimpleNodeTest:test_get_block:
#endunittest
#exercise
You have been sent some unknown number of sats to your address on signet.

Send all of it back (minus fees) to `mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv` using only the networking protocol.

This should be a 1 input, 1 output transaction.

Turn on logging in `SimpleNode` if you need to debug
---
>>> from block import Block
>>> from ecc import PrivateKey
>>> from helper import decode_base58, hash160, hash256, little_endian_to_int
>>> from network import GetDataMessage, SimpleNode, BLOCK_DATA_TYPE
>>> from script import p2pkh_script
>>> from tx import Tx, TxIn, TxOut
>>> block_hex = '0000013cacd6f0e096f8c059241f389211fc014bf7134ed0b83298788a86c9ad'  #/start_block_hex = '<insert from class>'  # CHANGE
>>> block_hash = bytes.fromhex(block_hex)
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
>>> # get the block object using the get_block method of node
>>> block_obj = node.get_block(block_hash)  #/
>>> # initialize the utxos array
>>> utxos = []  #/
>>> # grab the txs from the block using get_transactions
>>> txs = block_obj.get_transactions(my_script_pubkey)  #/
>>> # there should be one transaction
>>> if len(txs) != 1:
...     raise RuntimeError("incorrect number of transactions")
>>> # initialize the tx_ins array
>>> tx_ins = []  #/
>>> # loop through the outputs of the transaction, enumerated
>>> for i, tx_out in enumerate(txs[0].tx_outs):  #/
...     # check if the output has the script pubkey we're looking for
...     if tx_out.script_pubkey == my_script_pubkey:  #/
...         # add this tx out as a tx in  #/
...         tx_ins.append(TxIn(txs[0].hash(), i))  #/
...         # record the amount from this output
...         prev_amount = tx_out.amount  #/
>>> # calculate the output amount (prev amount - fee)
>>> output_amount = prev_amount - fee  #/
>>> # create TxOut
>>> tx_out = TxOut(output_amount, target_script)  #/
>>> # create transaction on signet
>>> tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet")  #/
>>> # sign the only input in the tx
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> # print the tx's id
>>> print(tx_obj.id())  #/
89b252427a527b955393aaaebe95f2d38c3367f9fd2415bf0fae3b4336fc7831
>>> # send this signed transaction via the node
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


def get_transactions(self, script_pubkey):
    if not self.txs:
        return []
    txs = []
    for t in self.txs:
        for tx_out in t.tx_outs:
            if tx_out.script_pubkey == script_pubkey:
                txs.append(t)
                break
    return txs


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
        Block.get_transactions = get_transactions


if __name__ == "__main__":
    import doctest

    doctest.testmod()
