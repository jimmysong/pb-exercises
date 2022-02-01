"""
#code
>>> import helper, op, script, tx

#endcode
#unittest
tx:TxTest:test_verify_p2pkh:
#endunittest
#code
>>> # Transaction Construction Example
>>> from ecc import PrivateKey
>>> from helper import decode_base58, SIGHASH_ALL
>>> from script import p2pkh_script, Script
>>> from tx import Tx, TxIn, TxOut
>>> # Step 1
>>> tx_ins = []
>>> prev_tx = bytes.fromhex('95ae966a54493321316799d5c4ba7f48faadd653b7eb725ea2c5ea7d38f65cff')
>>> prev_index = 0
>>> tx_ins.append(TxIn(prev_tx, prev_index))
>>> # Step 2
>>> tx_outs = []
>>> h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
>>> tx_outs.append(TxOut(
...     amount=int(0.37*100000000),
...     script_pubkey=p2pkh_script(h160),
... ))
>>> h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
>>> tx_outs.append(TxOut(
...     amount=int(0.1*100000000),
...     script_pubkey=p2pkh_script(h160),
... ))
>>> tx_obj = Tx(1, tx_ins, tx_outs, 0, network="signet")
>>> # Step 3
>>> z = tx_obj.sig_hash(0)
>>> pk = PrivateKey(secret=8675309)
>>> der = pk.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> sec = pk.point.sec()
>>> tx_obj.tx_ins[0].script_sig = Script([sig, sec])
>>> print(tx_obj.serialize().hex())
0100000001ff5cf6387deac5a25e72ebb753d6adfa487fbac4d5996731213349546a96ae95000000006a47304402204d7c693a6b7378795e005c25aac80b4beb4519903938614568d48d18bff7d88b0220269ad2ad8acb65ac68505bd9a92e43f5dd4e0011446802cdf6ccf71a4a03c481012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0240933402000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000

#endcode
#unittest
tx:TxTest:test_sign_input:
#endunittest
#exercise
You have been sent 100,000 Sats on the Signet network. Send 40,000 Sats to this address: `mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv` and send the rest back to yourself.

#### Send your transaction here: https://mempool.space/signet/tx/push
---
>>> from tx import Tx, TxIn, TxOut
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from script import p2pkh_script
>>> prev_tx = bytes.fromhex('d487dc425d0103aee99c46f8ab58a01ee99a19d9ce9f4db07e196597c4e73a29')  #/prev_tx = bytes.fromhex('<transaction id here>')  # CHANGE
>>> prev_index = 0  #/prev_index = -1  # CHANGE
>>> target_address = 'mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv'
>>> target_amount = 40000
>>> fee = 300
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> change_address = private_key.point.address(network="signet")
>>> # initialize inputs
>>> tx_ins = []  #/
>>> # create a new tx input with prev_tx, prev_index
>>> tx_ins.append(TxIn(prev_tx, prev_index))  #/
>>> # initialize outputs
>>> tx_outs = []  #/
>>> # decode the hash160 from the target address
>>> target_h160 = decode_base58(target_address)  #/
>>> # convert hash160 to p2pkh script
>>> target_script_pubkey = p2pkh_script(target_h160)  #/
>>> # create a new tx output for target with amount and script_pubkey
>>> tx_outs.append(TxOut(target_amount, target_script_pubkey))  #/
>>> # decode the hash160 from the change address
>>> change_h160 = decode_base58(change_address)  #/
>>> # convert hash160 to p2pkh script
>>> change_script_pubkey = p2pkh_script(change_h160)  #/
>>> # get the value for the transaction input (remember network="signet")
>>> prev_amount = tx_ins[0].value(network="signet")  #/
>>> # calculate change_amount based on previous amount, target_amount & fee
>>> change_amount = prev_amount - target_amount - fee  #/
>>> # create a new tx output for change with amount and script_pubkey
>>> tx_outs.append(TxOut(change_amount, change_script_pubkey))  #/
>>> # create the transaction (name it tx_obj and set network="signet")
>>> tx_obj = Tx(1, tx_ins, tx_outs, 0, network="signet")  #/
>>> # now sign the 0th input with the private_key using sign_input
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> # SANITY CHECK: change address corresponds to private key
>>> if private_key.point.address(network="signet") != change_address:
...     raise RuntimeError('Private Key does not correspond to Change Address, check priv_key and change_address')
>>> # SANITY CHECK: output's script_pubkey is the same one as your address
>>> if tx_ins[0].script_pubkey(network="signet").commands[2] != decode_base58(change_address):
...     raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')
>>> # SANITY CHECK: fee is reasonable
>>> if tx_obj.fee() > 100000 or tx_obj.fee() <= 0:
...     raise RuntimeError(f'Check that the change amount is reasonable. Fee is {tx_obj.fee()}')
>>> # serialize and hex()
>>> print(tx_obj.serialize().hex())  #/
0100000001293ae7c49765197eb04d9fced9199ae91ea058abf8469ce9ae03015d42dc87d4000000006b483045022100a906b77d1ed8e698a843800ec6a74e357687b0905b71eb2c75cb86b842305d6602203f3c50b5dd9375d3a9987f0742b2d50737447973252afccce561261afb2f804e012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff02409c0000000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac34e90000000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ac00000000

#endexercise
#exercise
#### Bonus Question. Only attempt if you've finished Exercise 3 and have time to try it.

Get some signet coins from a faucet and spend both outputs (one from your change address and one from the signet faucet) to

`mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv`

#### You can get some free signet coins at: https://signet.bc-2.jp/
---
>>> # Bonus
>>> from tx import Tx, TxIn, TxOut
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from script import p2pkh_script
>>> prev_tx_1 = bytes.fromhex('c2cfd11f33297c36c61f8911529b05fc14eab09e610461768f9eab6cc2576acf')  #/prev_tx_1 = bytes.fromhex('<tx id from last exercise>')  # CHANGE
>>> prev_index_1 = 1  #/prev_index_1 = -1  # CHANGE
>>> prev_tx_2 = bytes.fromhex('368941a52f2eb3a87b84b85396db0d2203a0eb32c95559d4249a8f02afa5e239')  #/prev_tx_2 = bytes.fromhex('<tx id from faucet>')  # CHANGE
>>> prev_index_2 = 0  #/prev_index_2 = -1  # CHANGE
>>> target_address = 'mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv'
>>> fee = 400
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> # initialize inputs
>>> tx_ins = []  #/
>>> # create the first tx input with prev_tx_1, prev_index_1
>>> tx_ins.append(TxIn(prev_tx_1, prev_index_1))  #/
>>> # create the second tx input with prev_tx_2, prev_index_2
>>> tx_ins.append(TxIn(prev_tx_2, prev_index_2))  #/
>>> # initialize outputs
>>> tx_outs = []  #/
>>> # decode the hash160 from the target address
>>> h160 = decode_base58(target_address)  #/
>>> # convert hash160 to p2pkh script
>>> script_pubkey = p2pkh_script(h160)  #/
>>> # calculate target amount by adding the input values and subtracting the fee
>>> target_satoshis = tx_ins[0].value(network="signet") + tx_ins[1].value(network="signet") - fee  #/
>>> # create a single tx output for target with amount and script_pubkey
>>> tx_outs.append(TxOut(target_satoshis, script_pubkey))  #/
>>> # create the transaction
>>> tx_obj = Tx(1, tx_ins, tx_outs, 0, network="signet")  #/
>>> # sign both inputs with the private key using sign_input
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> tx_obj.sign_input(1, private_key)  #/
True
>>> # SANITY CHECK: output's script_pubkey is the same one as your address
>>> if tx_ins[0].script_pubkey(network="signet").commands[2] != decode_base58(private_key.point.address(network="signet")):
...     raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')
>>> # SANITY CHECK: fee is reasonable
>>> if tx_obj.fee() > 100000 or tx_obj.fee() <= 0:
...     raise RuntimeError('Check that the change amount is reasonable. Fee is {tx_obj.fee()}')
>>> # serialize and hex()
>>> print(tx_obj.serialize().hex())  #/
0100000002cf6a57c26cab9e8f766104619eb0ea14fc059b5211891fc6367c29331fd1cfc2010000006b4830450221008447b4947a3014fffba1891d919d3997160b600b472242d1a92d5c009ec10efa02206f83e0f39272ac930d77f24ffa3bb062d3b6bcce26eb0c772d7f37efc41e0fcb012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff39e2a5af028f9a24d45955c932eba003220ddb9653b8847ba8b32e2fa5418936000000006b483045022100d688db2df75d4f9789d0a239c1aad58be12fa3d8d3622f4b67b57f7873a03e7a02206945042112cefe8bf337c925ee8f3c2d83341ead81450149271582d4cc522b5a012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff01446e0200000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000

#endexercise
#code
>>> # op_checkmultisig
>>> def op_checkmultisig(stack, z):
...     if len(stack) < 1:
...         return False
...     n = decode_num(stack.pop())
...     if len(stack) < n + 1:
...         return False
...     sec_pubkeys = []
...     for _ in range(n):
...         sec_pubkeys.append(stack.pop())
...     m = decode_num(stack.pop())
...     if len(stack) < m + 1:
...         return False
...     der_signatures = []
...     for _ in range(m):
...         # signature is assumed to be using SIGHASH_ALL
...         der_signatures.append(stack.pop()[:-1])
...     # OP_CHECKMULTISIG bug
...     stack.pop()
...     try:
...         raise NotImplementedError
...     except (ValueError, SyntaxError):
...         return False
...     return True

#endcode
#unittest
op:OpTest:test_op_checkmultisig:
#endunittest
#exercise
Find the hash160 of the RedeemScript
```
5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae
```
---
>>> from helper import hash160
>>> hex_redeem_script = '5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
>>> # bytes.fromhex script
>>> redeem_script = bytes.fromhex(hex_redeem_script)  #/
>>> # hash160 result
>>> h160 = hash160(redeem_script)  #/
>>> # hex() to display
>>> print(h160.hex())  #/
74d691da1574e6b3c192ecfb52cc8984ee7b6c56

#endexercise
#code
>>> # P2SH address construction example
>>> from helper import encode_base58_checksum
>>> print(encode_base58_checksum(b'\x05'+bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')))
3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh

#endcode
#unittest
helper:HelperTest:test_p2pkh_address:
#endunittest
#unittest
helper:HelperTest:test_p2sh_address:
#endunittest
#unittest
script:ScriptTest:test_address:
#endunittest
#code
>>> # z for p2sh example
>>> from helper import hash256
>>> h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
>>> z = int.from_bytes(h256, 'big')
>>> print(hex(z))
0xe71bfa115715d6fd33796948126f40a8cdd39f187e4afb03896795189fe1423c

#endcode
#code
>>> # p2sh verification example
>>> from ecc import S256Point, Signature
>>> from helper import hash256
>>> h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
>>> z = int.from_bytes(h256, 'big')
>>> point = S256Point.parse(bytes.fromhex('022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70'))
>>> sig = Signature.parse(bytes.fromhex('3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937'))
>>> print(point.verify(z, sig))
True

#endcode
#exercise
Validate the second signature of the first input

```
0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000
```

The sec pubkey of the second signature is:
```
03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71
```

The der signature of the second signature is:
```
3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022
```

The redeemScript is:
```
475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae
```
---
>>> from io import BytesIO
>>> from ecc import S256Point, Signature
>>> from helper import int_to_little_endian, SIGHASH_ALL
>>> from script import Script
>>> from tx import Tx
>>> hex_sec = '03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71'
>>> hex_der = '3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022'
>>> hex_redeem_script = '475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
>>> sec = bytes.fromhex(hex_sec)
>>> der = bytes.fromhex(hex_der)
>>> redeem_script_stream = BytesIO(bytes.fromhex(hex_redeem_script))
>>> redeem_script = Script.parse(redeem_script_stream)
>>> hex_tx = '0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000'
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> # parse the S256Point and Signature
>>> point = S256Point.parse(sec)  #/
>>> sig = Signature.parse(der)  #/
>>> # parse the Tx
>>> t = Tx.parse(stream)  #/
>>> # change the first input's ScriptSig to RedeemScript
>>> t.tx_ins[0].script_sig = redeem_script  #/
>>> # get the serialization
>>> ser = t.serialize()  #/
>>> # add the sighash (4 bytes, little-endian of SIGHASH_ALL)
>>> ser += int_to_little_endian(SIGHASH_ALL, 4)  #/
>>> # hash256 the result
>>> h256 = hash256(ser)  #/
>>> # your z is the hash256 as a big-endian number: use int.from_bytes(x, 'big')
>>> z = int.from_bytes(h256, 'big')  #/
>>> # now verify the signature using point.verify
>>> print(point.verify(z, sig))  #/
True

#endexercise
"""


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
    combined_script = tx_in.script_sig + tx_in.script_pubkey(self.network)
    return combined_script.evaluate(z)


def sign_input(self, input_index, private_key):
    z = self.sig_hash(input_index)
    der = private_key.sign(z).der()
    sig = der + SIGHASH_ALL.to_bytes(1, "big")
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


def h160_to_p2pkh_address(h160, network="mainnet"):
    if network in ("testnet", "signet"):
        prefix = b"\x6f"
    else:
        prefix = b"\x00"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, network="mainnet"):
    if network in ("testnet", "signet"):
        prefix = b"\xc4"
    else:
        prefix = b"\x05"
    return encode_base58_checksum(prefix + h160)


def is_p2pkh_script_pubkey(self):
    return (
        len(self.commands) == 5
        and self.commands[0] == 0x76
        and self.commands[1] == 0xA9
        and type(self.commands[2]) == bytes
        and len(self.commands[2]) == 20
        and self.commands[3] == 0x88
        and self.commands[4] == 0xAC
    )


def is_p2sh_script_pubkey(self):
    return (
        len(self.commands) == 3
        and self.commands[0] == 0xA9
        and type(self.commands[1]) == bytes
        and len(self.commands[1]) == 20
        and self.commands[2] == 0x87
    )


def address(self, network="mainnet"):
    if self.is_p2pkh_script_pubkey():
        h160 = self.commands[2]
        return h160_to_p2pkh_address(h160, network)
    elif self.is_p2sh_script_pubkey():
        h160 = self.commands[1]
        return h160_to_p2sh_address(h160, network)
    raise ValueError("Unknown ScriptPubKey")


class SessionTest(TestCase):
    def test_apply(self):
        Tx.verify_input = verify_input
        Tx.sign_input = sign_input
        op.op_checkmultisig = op_checkmultisig
        op.OP_CODE_FUNCTIONS[0xAE] = op_checkmultisig
        helper.h160_to_p2pkh_address = h160_to_p2pkh_address
        helper.h160_to_p2sh_address = h160_to_p2sh_address
        Script.is_p2pkh_script_pubkey = is_p2pkh_script_pubkey
        Script.is_p2sh_script_pubkey = is_p2sh_script_pubkey
        Script.address = address
