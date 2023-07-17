from io import BytesIO
from unittest import TestCase

import json
import requests

from ecc import PrivateKey
from helper import (
    decode_base58,
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    SIGHASH_ALL,
)
from script import p2pkh_script, Script


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, network="mainnet"):
        if network == "mainnet":
            return "http://blockstream.info/testnet/api"
        elif network == "signet":
            return "http://mempool.space/signet/api"
        else:
            return "http://blockstream.info/api"

    @classmethod
    def fetch(cls, tx_id, network="mainnet", fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = f"{cls.get_url(network)}/tx/{tx_id}/hex"
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(
                    f"unexpected response: {response.text} {url} {network}"
                )
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), network=network)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), network=network)
            # make sure the tx we got matches to the hash we requested
            if tx.id() != tx_id:
                raise ValueError(f"not the same id: {tx.id()} vs {tx_id}")
            cls.cache[tx_id] = tx
        cls.cache[tx_id].network = network
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, "r").read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = Tx.parse(BytesIO(bytes.fromhex(raw_hex)))

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, "w") as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    command = b"tx"
    define_network = True

    def __init__(
        self, version, tx_ins, tx_outs, locktime, network="mainnet", segwit=False
    ):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.network = network
        self.segwit = segwit

    def __repr__(self):
        tx_ins = " ".join([f"{tx_in}" for tx_in in self.tx_ins])
        tx_outs = " ".join([f"{tx_out}" for tx_out in self.tx_outs])
        return f"tx: {self.hash().hex()}\nversion: {self.version}\ntx_ins:\n{tx_ins}\ntx_outs:\n{tx_outs}\nlocktime: {self.locktime}\n"

    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s, network="mainnet"):
        """Parses a transaction from stream"""
        # we can determine whether something is segwit or legacy by looking
        # at byte 5
        s.read(4)
        if s.read(1) == b"\x00":
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # reset the seek to the beginning so everything can go through
        s.seek(-5, 1)
        return parse_method(s, network=network)

    @classmethod
    def parse_legacy(cls, s, network="mainnet"):
        """Takes a byte stream and parses a legacy transaction"""
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
        return cls(version, inputs, outputs, locktime, network=network, segwit=False)

    @classmethod
    def parse_segwit(cls, s, network="mainnet"):
        """Takes a byte stream and parses a segwit transaction"""
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # next two bytes need to be 0x00 and 0x01, otherwise raise RuntimeError
        marker = s.read(2)
        if marker != b"\x00\x01":
            raise RuntimeError("Not a segwit transaction {}".format(marker))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing, create inputs array
        inputs = []
        # parse each input and add to the inputs array
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing, create outputs array
        outputs = []
        # parse each output and add to the outputs array
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # there is a witness for each input
        for tx_in in inputs:
            tx_in.witness = Witness.parse(s)
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, network=network, segwit=True)

    def serialize(self):
        """Returns the byte serialization of the transaction"""
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        """Returns the fee of this transaction in satoshi"""
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value(self.network)
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""
        # create the serialization per spec
        # start with version: int_to_little_endian in 4 bytes
        s = int_to_little_endian(self.version, 4)
        # next, how many inputs there are: encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input: for i, tx_in in enumerate(self.tx_ins)
        for i, tx_in in enumerate(self.tx_ins):
            # if the input index is the one we're signing
            if i == input_index:
                # if the RedeemScript was passed in, that's the ScriptSig
                if redeem_script:
                    script_sig = redeem_script
                # otherwise the previous tx's ScriptPubkey is the ScriptSig
                else:
                    script_sig = tx_in.script_pubkey(self.network)
            # Otherwise, the ScriptSig is empty
            else:
                script_sig = None
            # create a new TxIn with the same parameters
            #  as tx_in, but change the script_sig
            new_tx_in = TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            )
            # add the serialization of the new TxIn
            s += new_tx_in.serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        s += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        s += int_to_little_endian(SIGHASH_ALL, 4)
        # hash256 the serialization
        h256 = hash256(s)
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(h256, "big")

    def verify_input(self, input_index):
        """Returns whether the input has a valid signature"""
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the script_pubkey of the input
        script_pubkey = tx_in.script_pubkey(network=self.network)
        # check to see if the script_pubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last command has to be the redeem script to trigger
            command = tx_in.script_sig.commands[-1]
            # parse the redeem script
            raw_redeem = int_to_little_endian(len(command), 1) + command
            redeem_script = Script.parse(BytesIO(raw_redeem))
        else:
            redeem_script = None
        # get the sig_hash (z)
        z = self.sig_hash(input_index, redeem_script)
        # combine the scripts
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.network)
        # evaluate the combined script
        return combined_script.evaluate(z)

    def verify(self):
        """Verify this transaction"""
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self, input_index, private_key):
        """Signs the input using the private key"""
        # get the sig_hash (z)
        z = self.sig_hash(input_index)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        # calculate the sec
        sec = private_key.point.sec()
        # initialize a new script with [sig, sec] as the elements
        script_sig = Script([sig, sec])
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self):
        """Returns whether this transaction is a coinbase transaction or not"""
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b"\x00" * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xFFFFFFFF:
            return False
        return True

    def coinbase_height(self):
        """Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        """
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first command of the script_sig (.script_sig.commands[0])
        first_command = first_input.script_sig.commands[0]
        # convert the first command from little endian to int
        return little_endian_to_int(first_command)

    def coinbase_block_subsidy(self):
        """Returns the calculated block subsidy of this coinbase transaction in Satoshis"""
        # grab the height using coinbase_height
        height = self.coinbase_height()
        # if the height is None return None
        if height is None:
            return None
        # calculate the epoch (height / 210,000) rounded down
        epoch = height // 210000
        # return the initial subsidy right-shifted by the epoch
        return 5000000000 >> epoch


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xFFFFFFFF):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return f"{self.prev_tx.hex()}:{self.prev_index}"

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        """
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_sig = Script.parse(s)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        """Returns the byte serialization of the transaction input"""
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, network="mainnet"):
        return TxFetcher.fetch(self.prev_tx.hex(), network=network)

    def value(self, network="mainnet"):
        """Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        """
        if self.prev_tx == b"\x00" * 32:
            return 0
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(network=network)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, network="mainnet"):
        """Get the scriptPubKey by looking up the tx hash
        Returns a Script object
        """
        if self.prev_tx == b"\x00" * 32:
            return Script()
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(network=network)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return f"{self.amount}:{self.script_pubkey}"

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        """
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_pubkey = Script.parse(s)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


class TxTest(TestCase):
    cache_file = "tx.cache"

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    def test_parse_version(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_ins), 1)
        want = bytes.fromhex(
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        )
        self.assertEqual(tx.tx_ins[0].prev_tx, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = bytes.fromhex(
            "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a"
        )
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xFFFFFFFE)

    def test_parse_outputs(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = bytes.fromhex("1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac")
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = bytes.fromhex("1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac")
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def test_serialize(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def test_input_value(self):
        tx_hash = "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_hash = "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        want = bytes.fromhex("1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac")
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def test_fee(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = bytes.fromhex(
            "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = int(
            "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6", 16
        )
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_p2pkh(self):
        tx = TxFetcher.fetch(
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03"
        )
        self.assertTrue(tx.verify())
        tx = TxFetcher.fetch(
            "5418099cc755cb9dd3ebc6cf1a7888ad53a1a3beb5a025bce89eb1bf7f1650a2",
            network="testnet",
        )
        self.assertTrue(tx.verify())

    def test_verify_p2sh(self):
        tx = TxFetcher.fetch(
            "46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b"
        )
        self.assertTrue(tx.verify())

    def test_sign_input(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex(
            "0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8"
        )
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2")
        tx_outs.append(
            TxOut(amount=int(0.99 * 100000000), script_pubkey=p2pkh_script(h160))
        )
        h160 = decode_base58("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf")
        tx_outs.append(
            TxOut(amount=int(0.1 * 100000000), script_pubkey=p2pkh_script(h160))
        )

        tx = Tx(1, tx_ins, tx_outs, 0, network="testnet")
        self.assertTrue(tx.sign_input(0, private_key))

    def test_is_coinbase(self):
        raw_tx = bytes.fromhex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        raw_tx = bytes.fromhex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.coinbase_height(), 465879)
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertIsNone(tx.coinbase_height())

    def test_coinbase_block_subsidy(self):
        raw_tx = bytes.fromhex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.coinbase_block_subsidy(), 1250000000)
        raw_tx = bytes.fromhex(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        )
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertIsNone(tx.coinbase_block_subsidy())
