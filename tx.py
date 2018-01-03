from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase

import random
import requests

from ecc import PrivateKey, S256Point, Signature
from helper import (
    decode_base58,
    double_sha256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    p2pkh_script,
    read_varint,
    SIGHASH_ALL,
)
from script import Script

class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'version: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime)

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value()
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a new set of tx_ins (alt_tx_ins)
        alt_tx_ins = []
        # iterate over self.tx_ins
        for tx_in in self.tx_ins:
            # create a new TxIn that has a blank script_sig (b'') and add to alt_tx_ins
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
            ))
        # grab the input at the input_index
        signing_input = alt_tx_ins[input_index]
        # grab the script_pubkey of the input
        script_pubkey = signing_input.script_pubkey(self.testnet)
        # Exercise 6.2: get the sig type from script_pubkey.type()
        sig_type = script_pubkey.type()
        # Exercise 6.2: the script_sig of the signing_input should be script_pubkey for p2pkh
        if sig_type == 'p2pkh':
            # Exercise 6.2: replace the input's scriptSig with the scriptPubKey
            signing_input.script_sig = script_pubkey
        # Exercise 6.2: the script_sig of the signing_input should be the redeemScript
        #               of the current input of the real tx_in (self.tx_ins[input_index].redeem_script()
        elif sig_type == 'p2sh':
            # Exercise 6.2: replace the input's scriptSig with the RedeemScript
            current_input = self.tx_ins[input_index]
            # Exercise 6.2: replace the input's scriptSig with the Script.parse(redeem_script)
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('no valid sig_type')
        # create an alternate transaction with the modified tx_ins
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime)
        # add the hash_type int 4 bytes, little endian
        result = alt_tx.serialize() + int_to_little_endian(hash_type, 4)
        # get the double_sha256 of the tx serialization
        s256 = double_sha256(result)
        # convert this to a big-endian integer using int.from_bytes(x, 'big')
        return int.from_bytes(s256, 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # Exercise 1.1: get the relevant input
        tx_in = self.tx_ins[input_index]
        # Exercise 6.2: get the number of signatures required. This is available in tx_in.script_sig.num_sigs_required()
        sigs_required = tx_in.script_sig.num_sigs_required()
        # Exercise 6.2: iterate over the sigs required and check each signature
        for sig_num in range(sigs_required):
            # Exercise 1.1: get the point from the sec format (tx_in.sec_pubkey())
            # Exercise 6.2: get the sec_pubkey at current signature index (check sec_pubkey function)
            point = S256Point.parse(tx_in.sec_pubkey(index=sig_num))
            # Exercise 1.1: get the der sig and hash_type from input
            # Exercise 6.2: get the der_signature at current signature index (check der_signature function)
            der, hash_type = tx_in.der_signature(index=sig_num)
            # Exercise 1.1: get the signature from der format
            signature = Signature.parse(der)
            # Exercise 1.1: get the hash to sign
            z = self.sig_hash(input_index, hash_type)
            # Exercise 1.1: use point.verify on the hash to sign and signature
            if not point.verify(z, signature):
                return False
        return True

    def sign_input(self, input_index, private_key, hash_type):
        '''Signs the input using the private key'''
        # get the hash to sign
        z = self.sig_hash(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec()
        # initialize a new script with [sig, sec] as the elements
        script_sig = Script([sig, sec])
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first element of the script_sig (.script_sig.elements[0])
        first_element = first_input.script_sig.elements[0]
        # convert the first element from little endian to int
        return little_endian_to_int(first_element)


class TxIn:

    cache = {}

    def __init__(self, prev_tx, prev_index, script_sig, sequence):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = Script.parse(script_sig)
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            hexlify(self.prev_tx).decode('ascii'),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_sig_length = read_varint(s)
        script_sig = s.read(script_sig_length)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # get the scriptSig ready (use self.script_sig.serialize())
        raw_script_sig = self.script_sig.serialize()
        # encode_varint on the length of the scriptSig
        result += encode_varint(len(raw_script_sig))
        # add the scriptSig
        result += raw_script_sig
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://testnet.blockexplorer.com/api'
        else:
            return 'https://btc-bitcore3.trezor.io/api'

    def fetch_tx(self, testnet=False):
        if self.prev_tx not in self.cache:
            url = self.get_url(testnet) + '/rawtx/{}'.format(hexlify(self.prev_tx).decode('ascii'))
            response = requests.get(url)
            js_response = response.json()
            if 'rawtx' not in js_response:
                raise RuntimeError('got from server: {}'.format(js_response))
            raw = unhexlify(js_response['rawtx'])
            stream = BytesIO(raw)
            tx = Tx.parse(stream)
            self.cache[self.prev_tx] = tx
        return self.cache[self.prev_tx]

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash on libbitcoin server
        Returns the amount in satoshi
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash on libbitcoin server
        Returns the binary scriptpubkey
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property and serialize
        return tx.tx_outs[self.prev_index].script_pubkey

    def der_signature(self, index=0):
        '''returns a DER format signature and hash_type if the script_sig
        has a signature'''
        signature = self.script_sig.der_signature(index=index)
        # last byte is the hash_type, rest is the signature
        return signature[:-1], signature[-1]

    def sec_pubkey(self, index=0):
        '''returns the SEC format public if the script_sig has one'''
        return self.script_sig.sec_pubkey(index=index)

    def redeem_script(self):
        '''return the Redeem Script if there is one'''
        return self.script_sig.redeem_script()


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = Script.parse(script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey.address())

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_pubkey_length = read_varint(s)
        script_pubkey = s.read(script_pubkey_length)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # get the scriptPubkey ready (use self.script_pubkey.serialize())
        raw_script_pubkey = self.script_pubkey.serialize()
        # encode_varint on the length of the scriptPubkey
        result += encode_varint(len(raw_script_pubkey))
        # add the scriptPubKey
        result += raw_script_pubkey
        return result


class TxTest(TestCase):

    def test_parse_version(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_ins), 1)
        want = unhexlify('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
        self.assertEqual(tx.tx_ins[0].prev_tx, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = unhexlify('483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = unhexlify('76a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = unhexlify('76a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def test_der_signature(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = b'3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed'
        der, hash_type = tx.tx_ins[0].der_signature()
        self.assertEqual(hexlify(der), want)
        self.assertEqual(hash_type, SIGHASH_ALL)

    def test_sec_pubkey(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = b'0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
        self.assertEqual(hexlify(tx.tx_ins[0].sec_pubkey()), want)

    def test_serialize(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def test_input_value(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(
            prev_tx=unhexlify(tx_hash),
            prev_index=index,
            script_sig=b'',
            sequence=0,
        )
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(
            prev_tx=unhexlify(tx_hash),
            prev_index=index,
            script_sig=b'',
            sequence=0,
        )
        want = unhexlify('76a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac')
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def test_fee(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = unhexlify('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        hash_type = SIGHASH_ALL
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0, hash_type), want)

    def test_verify_input1(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input2(self):
        raw_tx = unhexlify('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.verify_input(0))

    def test_sign_input(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = unhexlify('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(
            prev_tx=prev_tx,
            prev_index=0,
            script_sig = b'',
            sequence = 0xffffffff,
        ))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99*100000000), script_pubkey=p2pkh_script(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1*100000000), script_pubkey=p2pkh_script(h160)))

        tx = Tx(
            version=1,
            tx_ins=tx_ins,
            tx_outs=tx_outs,
            locktime=0,
            testnet=True,
        )
        self.assertTrue(tx.sign_input(0, private_key, SIGHASH_ALL))

    def test_is_coinbase(self):
        raw_tx = unhexlify('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        raw_tx = unhexlify('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.coinbase_height(), 465879)
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertIsNone(tx.coinbase_height())
