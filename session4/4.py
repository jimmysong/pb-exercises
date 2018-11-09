from io import BytesIO
from unittest import TestCase

import op

from ecc import S256Point, Signature
from helper import (
    encode_varint,
    hash160,
    hash256,
    int_to_little_endian,
    SIGHASH_ALL,
)
from op import encode_num
from script import Script
from tx import Tx, TxIn, TxOut


def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    der_signature = stack.pop()[:-1]
    point = S256Point.parse(sec_pubkey)
    sig = Signature.parse(der_signature)
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def serialize_tx(self):
    result = int_to_little_endian(self.version, 4)
    result += encode_varint(len(self.tx_ins))
    for tx_in in self.tx_ins:
        result += tx_in.serialize()
    result += encode_varint(len(self.tx_outs))
    for tx_out in self.tx_outs:
        result += tx_out.serialize()
    result += int_to_little_endian(self.locktime, 4)
    return result


def serialize_txin(self):
    result = self.prev_tx[::-1]
    result += int_to_little_endian(self.prev_index, 4)
    result += self.script_sig.serialize()
    result += int_to_little_endian(self.sequence, 4)
    return result


def serialize_txout(self):
    result = int_to_little_endian(self.amount, 8)
    result += self.script_pubkey.serialize()
    return result


def value(self, testnet=False):
    tx = self.fetch_tx(testnet=testnet)
    return tx.tx_outs[self.prev_index].amount


def script_pubkey(self, testnet=False):
    tx = self.fetch_tx(testnet=testnet)
    return tx.tx_outs[self.prev_index].script_pubkey


def fee(self):
    input_sum, output_sum = 0, 0
    for tx_in in self.tx_ins:
        input_sum += tx_in.value(self.testnet)
    for tx_out in self.tx_outs:
        output_sum += tx_out.amount
    return input_sum - output_sum


def sig_hash(self, input_index):
    alt_tx_ins = []
    for tx_in in self.tx_ins:
        alt_tx_ins.append(TxIn(
            prev_tx=tx_in.prev_tx,
            prev_index=tx_in.prev_index,
            sequence=tx_in.sequence,
        ))
    signing_input = alt_tx_ins[input_index]
    script_pubkey = signing_input.script_pubkey(self.testnet)
    signing_input.script_sig = script_pubkey
    alt_tx = self.__class__(
        version=self.version,
        tx_ins=alt_tx_ins,
        tx_outs=self.tx_outs,
        locktime=self.locktime)
    result = alt_tx.serialize() + int_to_little_endian(SIGHASH_ALL, 4)
    h256 = hash256(result)
    return int.from_bytes(h256, 'big')


class Session4Test(TestCase):

    def test_apply(self):
        op.op_hash160 = op_hash160
        op.OP_CODE_FUNCTIONS[0xa9] = op_hash160
        op.op_checksig = op_checksig
        op.OP_CODE_FUNCTIONS[0xac] = op_checksig
        Tx.serialize = serialize_tx
        TxIn.serialize = serialize_txin
        TxOut.serialize = serialize_txout
        TxIn.value = value
        TxIn.script_pubkey = script_pubkey
        Tx.fee = fee
        Tx.sig_hash = sig_hash

    def test_example_1(self):
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
        sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')
        script_pubkey = Script([sec, 0xac])
        script_sig = Script([sig])
        combined_script = script_sig + script_pubkey
        self.assertTrue(combined_script.evaluate(z))

    def test_example_2(self):
        hex_script_pubkey = '0455935987'
        script_pubkey = Script.parse(BytesIO(bytes.fromhex(hex_script_pubkey)))
        hex_script_sig = '0154'
        script_sig = Script.parse(BytesIO(bytes.fromhex(hex_script_sig)))
        combined_script = script_sig + script_pubkey
        self.assertTrue(combined_script.evaluate(0))

    def test_exercise_3(self):
        hex_script_pubkey = '06767695935687'
        bin_script_pubkey = bytes.fromhex(hex_script_pubkey)
        stream = BytesIO(bin_script_pubkey)
        script_pubkey = Script.parse(stream)
        script_sig = Script.parse(BytesIO(bytes.fromhex('0152')))
        combined_script = script_sig + script_pubkey
        self.assertTrue(combined_script.evaluate(0))

    def test_exercise_4(self):
        hex_script_pubkey = '086e879169a77ca787'
        script_pubkey = Script.parse(BytesIO(bytes.fromhex(hex_script_pubkey)))
        hex_script_sig = 'fd86024d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a14d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1'
        script_sig = Script.parse(BytesIO(bytes.fromhex(hex_script_sig)))
        combined_script = script_sig + script_pubkey
        self.assertTrue(combined_script.evaluate(0))

    def test_exercise_6(self):
        prev_tx = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81') 
        prev_index = 0
        tx_in = TxIn(prev_tx, 0)
        t = tx_in.fetch_tx()
        prev_output = t.tx_outs[prev_index]
        self.assertEqual(prev_output.amount, 42505594)
        want = [0x76, 0xa9, bytes.fromhex('a802fc56c704ce87c42d7c92eb75e7896bdc41ae'), 0x88, 0xac]
        self.assertEqual(prev_output.script_pubkey.instructions, want)

    def test_exercise_7(self):
        hex_tx = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600'
        stream = BytesIO(bytes.fromhex(hex_tx))
        t = Tx.parse(stream)
        input_sum = 0
        for tx_in in t.tx_ins:
            value = tx_in.value()
            input_sum += value
        output_sum = 0
        for tx_out in t.tx_outs:
            value = tx_out.amount
            output_sum += value
        fee = input_sum - output_sum
        self.assertEqual(fee, 140500)

    def test_example_3(self):
        modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
        h = hash256(modified_tx)
        z = int.from_bytes(h, 'big')
        self.assertEqual(z, 0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6)

    def test_example_4(self):
        modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
        h256 = hash256(modified_tx)
        z = int.from_bytes(h256, 'big')
        stream = BytesIO(bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'))
        transaction = Tx.parse(stream)
        tx_in = transaction.tx_ins[0]
        combined_script = tx_in.script_sig + tx_in.script_pubkey()
        self.assertTrue(combined_script.evaluate(z))

    def test_exercise_9(self):
        hex_tx = '01000000012f5ab4d2666744a44864a63162060c2ae36ab0a2375b1c2b6b43077ed5dcbed6000000006a473044022034177d53fcb8e8cba62432c5f6cc3d11c16df1db0bce20b874cfc61128b529e1022040c2681a2845f5eb0c46adb89585604f7bf8397b82db3517afb63f8e3d609c990121035e8b10b675477614809f3dde7fd0e33fb898af6d86f51a65a54c838fddd417a5feffffff02c5872e00000000001976a91441b835c78fb1406305727d8925ff315d90f9bbc588acae2e1700000000001976a914c300e84d277c6c7bcf17190ebc4e7744609f8b0c88ac31470600'
        stream = BytesIO(bytes.fromhex(hex_tx))
        index = 0
        t = Tx.parse(stream)
        tx_in = t.tx_ins[index]
        z = t.sig_hash(index)
        combined_script = tx_in.script_sig + tx_in.script_pubkey()
        self.assertTrue(combined_script.evaluate(z))
