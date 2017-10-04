from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase, skip

import requests

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
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

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        version = little_endian_to_int(s.read(4))
        num_inputs = s.read(1)[0]
        tx_ins = []
        for _ in range(num_inputs):
            tx_ins.append(TxIn.parse(s))
        num_outputs = s.read(1)[0]
        tx_outs = []
        for _ in range(num_outputs):
            tx_outs.append(TxOut.parse(s))
        sequence = little_endian_to_int(s.read(4))
        return cls(version, tx_ins, tx_outs, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        # version
        result = int_to_little_endian(self.version, 4)
        # inputs
        result += bytes([len(self.tx_ins)])
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        # outputs
        result += bytes([len(self.tx_outs)])
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        # locktime
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        input_sum = 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        output_sum = 0
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    def hash_to_sign(self, input_index, sighash):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        signing_input.script_sig = Script.parse(
            signing_input.script_pubkey(self.testnet))
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime)
        # add the sighash
        result = alt_tx.serialize() + int_to_little_endian(sighash, 4)
        return int.from_bytes(double_sha256(result), 'big')


CACHE = {'75d7454b7010fa28b00f16cccb640b1756fd6e357c03a3b81b9d119505f47b56:0': {'script': '76a914cd0b3a22cd16e182291aa2708c41cb38de5a330788ac', 'addresses': ['1KhAyQ3kaRQptGwAZghHBjNg65dgGdDXak'], 'value': 1043341, 'script_type': 'pay-to-pubkey-hash', 'spent_by': 'ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87'}, 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81:0': {'script': '76a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac', 'addresses': ['1GKN6gJBgvet8S92qiQjVxEaVJ5eoJE9s2'], 'value': 42505594, 'script_type': 'pay-to-pubkey-hash', 'spent_by': '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03'}, 'd37f9e7282f81b7fd3af0fde8b462a1c28024f1d83cf13637ec18d03f4518fe:0': {'script': '76a914af24b3f3e987c23528b366122a7ed2af199b36bc88ac', 'addresses': ['1Gy5Djegn51WxHQN4X19FBsUy8RQ74hvYo'], 'value': 29960102, 'script_type': 'pay-to-pubkey-hash', 'spent_by': 'ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87'}, '45f3f79066d251addc04fd889f776c73afab1cb22559376ff820e6166c5e3ad6:1': {'script': '76a914311b232c3400080eb2636edb8548b47f6835be7688ac', 'addresses': ['15UecwTDg57tnfSM6Cra8cmZVYavxtTZp2'], 'value': 9337330, 'script_type': 'pay-to-pubkey-hash', 'spent_by': 'ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87'}, '9e067aedc661fca148e13953df75f8ca6eada9ce3b3d8d68631769ac60999156:1': {'script': '76a914677345c7376dfda2c52ad9b6a153b643b6409a3788ac', 'addresses': ['1ARzh3A5fgGzbaXkg3novtH8AopzojY79D'], 'value': 800000, 'script_type': 'pay-to-pubkey-hash', 'spent_by': 'ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87'}, '0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8:0': {'script': '76a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac', 'value': 110000000, 'script_type': 'pay-to-pubkey-hash', 'addresses': ['mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2']}}


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig, sequence):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = Script.parse(script_sig)
        self.sequence = sequence

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # previous tx is little endian
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig_length = s.read(1)[0]
        script_sig = s.read(script_sig_length)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # tx, prev_tx is little-endian!
        result = self.prev_tx[::-1] + int_to_little_endian(self.prev_index, 4)
        # script_sig
        serialized_script_sig = self.script_sig.serialize()
        result += bytes([len(serialized_script_sig)]) + serialized_script_sig
        # sequence
        result += int_to_little_endian(self.sequence, 4)
        return result

    def outpoint(self, testnet=False):
        cache_key = '{}:{}'.format(
            hexlify(self.prev_tx).decode('ascii'), self.prev_index)
        cache = CACHE.get(cache_key)
        if cache:
            return cache
        if testnet:
            net = 'test3'
        else:
            net = 'main'
        url = 'https://api.blockcypher.com/v1/btc/{}/txs/{}?token=41298c19cc85400da2f1aa620578b096'.format(
            net, hexlify(self.prev_tx).decode('ascii'))
        tx_json = requests.get(url).json()
        if 'outputs' not in tx_json:
            raise RuntimeError('received {}'.format(tx_json))
        CACHE[cache_key] = tx_json['outputs'][self.prev_index]
        return CACHE[cache_key]

    def value(self, testnet=False):
        '''tx_hash is a hex version of tx, index is an integer
        get the outpoint value by looking up the tx_hash on blockcypher.com.
        Returns the amount in satoshi
        '''
        # might be useful
        # requests.get(url).json()
        outpoint = self.outpoint(testnet=testnet)
        return outpoint['value']

    def script_pubkey(self, testnet=False):
        '''tx_hash is a hex version of tx, index is an integer
        get the scriptPubKey by looking up the transaction on blockcypher.com.
        Returns the binary scriptpubkey
        '''
        # might be useful
        # requests.get(url).json()
        outpoint = self.outpoint(testnet=testnet)
        return unhexlify(outpoint['script'])

    def der_signature(self, index=0):
        '''returns a DER format signature and sighash if the script_sig
        has a signature'''
        signature = self.script_sig.der_signature(index=index)
        # last byte is the sighash, rest is the signature
        return signature[:-1], signature[-1]

    def sec_pubkey(self, index=0):
        '''returns the SEC format public if the script_sig has one'''
        return self.script_sig.sec_pubkey(index=index)


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = Script.parse(script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        amount = little_endian_to_int(s.read(8))
        script_pubkey_length = s.read(1)[0]
        script_pubkey = s.read(script_pubkey_length)
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # amount
        result = int_to_little_endian(self.amount, 8)
        # pubkey
        serialized_script_pubkey = self.script_pubkey.serialize()
        result += bytes([len(serialized_script_pubkey)]) + serialized_script_pubkey
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
        der, sighash = tx.tx_ins[0].der_signature()
        self.assertEqual(hexlify(der), want)
        self.assertEqual(sighash, SIGHASH_ALL)

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
        self.assertEqual(tx_in.script_pubkey(), want)

    def test_fee(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = unhexlify('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def test_hash_to_sign(self):
        raw_tx = unhexlify('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        sighash = SIGHASH_ALL
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.hash_to_sign(0, sighash), want)
