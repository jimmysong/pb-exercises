from io import BytesIO
from unittest import TestCase

import helper
import op


from ecc import (
    PrivateKey,
    S256Point,
    Signature,
)
from helper import (
    decode_base58,
    encode_base58_checksum,
    hash160,
    hash256,
    int_to_little_endian,
    SIGHASH_ALL,
)
from op import (
    decode_num,
    encode_num,
)
from script import (
    p2pkh_script,
    Script,
)
from tx import (
    Tx,
    TxIn,
    TxOut,
)


def verify_input(self, input_index):
    tx_in = self.tx_ins[input_index]
    z = self.sig_hash(input_index)
    combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
    return combined_script.evaluate(z)


def sign_input(self, input_index, private_key):
    z = self.sig_hash(input_index)
    der = private_key.sign(z).der()
    sig = der + SIGHASH_ALL.to_bytes(1, 'big')
    sec = private_key.point.sec()
    script_sig = Script([sig, sec])
    self.tx_ins[input_index].script_sig = script_sig
    return self.verify_input(input_index)


def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])
    stack.pop()
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            if len(points) == 0:
                print("signatures no good or not in right order")
                return False
            while points:
                point = points.pop(0)
                if point.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)


def is_p2pkh_script_pubkey(self):
    return len(self.instructions) == 5 and self.instructions[0] == 0x76 \
        and self.instructions[1] == 0xa9 \
        and type(self.instructions[2]) == bytes and len(self.instructions[2]) == 20 \
        and self.instructions[3] == 0x88 and self.instructions[4] == 0xac


def is_p2sh_script_pubkey(self):
    return len(self.instructions) == 3 and self.instructions[0] == 0xa9 \
        and type(self.instructions[1]) == bytes and len(self.instructions[1]) == 20 \
        and self.instructions[2] == 0x87


def address(self, testnet=False):
    if self.is_p2pkh_script_pubkey():
        h160 = self.instructions[2]
        return h160_to_p2pkh_address(h160, testnet)
    elif self.is_p2sh_script_pubkey():
        h160 = self.instructions[1]
        return h160_to_p2sh_address(h160, testnet)
    raise ValueError('Unknown ScriptPubKey')


class Session5Test(TestCase):

    def test_apply(self):
        Tx.verify_input = verify_input
        Tx.sign_input = sign_input
        op.op_checkmultisig = op_checkmultisig
        op.OP_CODE_FUNCTIONS[0xae] = op_checkmultisig
        helper.h160_to_p2pkh_address = h160_to_p2pkh_address
        helper.h160_to_p2sh_address = h160_to_p2sh_address
        Script.is_p2pkh_script_pubkey = is_p2pkh_script_pubkey
        Script.is_p2sh_script_pubkey = is_p2sh_script_pubkey
        Script.address = address

    def test_example_1(self):
        tx_ins = []
        prev_tx = bytes.fromhex('8be2f69037de71e3bc856a6627ed3e222a7a2d0ce81daeeb54a3aea8db274149')
        prev_index = 4
        tx_ins.append(TxIn(prev_tx, prev_index))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(
            amount=int(0.38*100000000),
            script_pubkey=p2pkh_script(h160),
        ))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(
            amount=int(0.1*100000000),
            script_pubkey=p2pkh_script(h160),
        ))
        tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
        z = tx_obj.sig_hash(0)
        pk = PrivateKey(secret=8675309)
        der = pk.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = pk.point.sec()
        tx_obj.tx_ins[0].script_sig = Script([sig, sec])
        want = '0100000001494127dba8aea354ebae1de80c2d7a2a223eed27666a85bce371de3790f6e28b040000006b483045022100fa3032607b50e8cb05bedc9d43f986f19dedc22e61320b9765061c5cd9c66946022072d514ef637988515bfa59a660596206de68f0ed4090d0a398e70f4d81370dfb012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0280d54302000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)

    def test_exercise_3_1(self):
        prev_tx = bytes.fromhex('eb581753a4dbd6befeaaaa28a6f4576698ba13a07c03da693a65bce11cf9887a')
        prev_index = 1
        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
        target_amount = 0.04
        change_address = 'mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2'
        fee = 50000
        secret = 8675309
        private_key = PrivateKey(secret=secret)
        tx_ins = []
        tx_ins.append(TxIn(prev_tx, prev_index))
        tx_outs = []
        h160 = decode_base58(target_address)
        script_pubkey = p2pkh_script(h160)
        target_satoshis = int(target_amount*100000000)
        tx_outs.append(TxOut(target_satoshis, script_pubkey))
        h160 = decode_base58(change_address)
        script_pubkey = p2pkh_script(h160)
        prev_amount = tx_ins[0].value(testnet=True)
        change_satoshis = prev_amount - target_satoshis - fee
        tx_outs.append(TxOut(change_satoshis, script_pubkey))
        tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
        tx_obj.sign_input(0, private_key)
        if private_key.point.address(testnet=True) != change_address:
            raise RuntimeError('Private Key does not correspond to Change Address, check priv_key and change_address')
        if tx_ins[0].script_pubkey(testnet=True).instructions[2] != decode_base58(change_address):
            raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')
        if tx_obj.fee() > 0.05*100000000 or tx_obj.fee() <= 0:
            raise RuntimeError('Check that the change amount is reasonable. Fee is {}'.format(tx_obj.fee()))
        self.assertEqual(tx_obj.serialize().hex(), '01000000017a88f91ce1bc653a69da037ca013ba986657f4a628aaaafebed6dba4531758eb010000006a47304402204ce6e3877ed2e18d2165276cbdba241507ce72b44d8df640eb6cb4d415eaaea002207dffd162da35593d86188ce87a1cbc9d3a5b26391870f19bf1764ca05b315ad9012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0200093d00000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac7077e401000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac00000000')

    def test_exercise_3_2(self):
        prev_tx_1 = bytes.fromhex('89cbfe2eddaddf1eb11f5c4adf6adaa9bca4adc01b2a3d03f8dd36125c068af4')
        prev_index_1 = 0
        prev_tx_2 = bytes.fromhex('19069e1304d95f70e03311d9d58ee821e0978e83ecfc47a30af7cd10fca55cf4')
        prev_index_2 = 0
        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
        fee = 50000
        secret = 61740721216174072121
        private_key = PrivateKey(secret=secret)
        tx_ins = []
        tx_ins.append(TxIn(prev_tx_1, prev_index_1))
        tx_ins.append(TxIn(prev_tx_2, prev_index_2))
        tx_outs = []
        h160 = decode_base58(target_address)
        script_pubkey = p2pkh_script(h160)
        target_satoshis = tx_ins[0].value(True) + tx_ins[1].value(True) - fee
        tx_outs.append(TxOut(target_satoshis, script_pubkey))
        tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
        tx_obj.sign_input(0, private_key)
        tx_obj.sign_input(1, private_key)
        if tx_ins[0].script_pubkey(testnet=True).instructions[2] != decode_base58(private_key.point.address(testnet=True)):
            raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')
        if tx_obj.fee() > 0.05*100000000 or tx_obj.fee() <= 0:
            raise RuntimeError('Check that the change amount is reasonable. Fee is {}'.format(tx_obj.fee()))
        self.assertEqual(tx_obj.serialize().hex(), '0100000002f48a065c1236ddf8033d2a1bc0ada4bca9da6adf4a5c1fb11edfaddd2efecb89000000006a47304402204b9ee431a2f5deaefb5282a34d7dcfdb47d55b1e3ce00cac4c6b6e6f0f0e8d58022062710e84786d2c6c89ddda5a149b45088b15230c6b825f0f21490f99bd74c81d012103f96f3a1efd31e1a8d7078118ee56bff7355d58907ce0f865f5f0b3dbe34e55befffffffff45ca5fc10cdf70aa347fcec838e97e021e88ed5d91133e0705fd904139e0619000000006a473044022073d7217b2d582e55978284c2628015a14e3490e835c76488eb29b63de15d17920220384e4b5282c911273efd4d98170e7092e10a729d142db17f4725c15364fa4ecc012103f96f3a1efd31e1a8d7078118ee56bff7355d58907ce0f865f5f0b3dbe34e55beffffffff01021f320a000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000')

    def test_exercise_5(self):
        hex_redeem_script = '5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
        redeem_script = bytes.fromhex(hex_redeem_script)
        h160 = hash160(redeem_script)
        self.assertEqual(h160.hex(), '74d691da1574e6b3c192ecfb52cc8984ee7b6c56')

    def test_example_3(self):
        self.assertEqual(encode_base58_checksum(b'\x05'+bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')), '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh')

    def test_example_4(self):
        h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
        z = int.from_bytes(h256, 'big')
        self.assertEqual(z, 0xe71bfa115715d6fd33796948126f40a8cdd39f187e4afb03896795189fe1423c)

    def test_example_5(self):
        h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
        z = int.from_bytes(h256, 'big')
        point = S256Point.parse(bytes.fromhex('022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70'))
        sig = Signature.parse(bytes.fromhex('3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937'))
        self.assertTrue(point.verify(z, sig))

    def test_exercise_6(self):
        hex_sec = '03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71'
        hex_der = '3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022'
        hex_redeem_script = '475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
        sec = bytes.fromhex(hex_sec)
        der = bytes.fromhex(hex_der)
        redeem_script_stream = BytesIO(bytes.fromhex(hex_redeem_script))
        hex_tx = '0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000'
        stream = BytesIO(bytes.fromhex(hex_tx))
        point = S256Point.parse(sec)
        sig = Signature.parse(der)
        t = Tx.parse(stream)
        t.tx_ins[0].script_sig = Script.parse(redeem_script_stream)
        ser = t.serialize()
        ser += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(ser)
        z = int.from_bytes(h256, 'big')
        self.assertTrue(point.verify(z, sig))
