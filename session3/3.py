from io import BytesIO
from random import randint
from unittest import TestCase

from ecc import (
    G,
    N,
    PrivateKey,
    S256Point,
    Signature,
)
from helper import (
    hash256,
    little_endian_to_int,
    read_varint,
)
from script import Script
from tx import Tx, TxIn, TxOut


def verify(self, z, sig):
    s_inv = pow(sig.s, N - 2, N)
    u = z * s_inv % N
    v = sig.r * s_inv % N
    total = u * G + v * self
    return total.x.num == sig.r


def sign(self, z):
    k = randint(0, N)
    r = (k * G).x.num
    k_inv = pow(k, N - 2, N)
    s = (z + r * self.secret) * k_inv % N
    if s > N / 2:
        s = N - s
    return Signature(r, s)


@classmethod
def parse_tx(cls, s):
    '''Takes a byte stream and parses the transaction at the start
    return a Tx object
    '''
    version = little_endian_to_int(s.read(4))
    num_inputs = read_varint(s)
    inputs = []
    for _ in range(num_inputs):
        inputs.append(TxIn.parse(s))
    num_outputs = read_varint(s)
    outputs = []
    for _ in range(num_outputs):
        outputs.append(TxOut.parse(s))
    locktime = little_endian_to_int(s.read(4))
    return cls(version, inputs, outputs, locktime)


@classmethod
def parse_txin(cls, s):
    '''Takes a byte stream and parses the tx_input at the start
    return a TxIn object
    '''
    prev_tx = s.read(32)[::-1]
    prev_index = little_endian_to_int(s.read(4))
    script_sig = Script.parse(s)
    sequence = little_endian_to_int(s.read(4))
    return cls(prev_tx, prev_index, script_sig, sequence)


@classmethod
def parse_txout(cls, s):
    amount = little_endian_to_int(s.read(8))
    script_pubkey = Script.parse(s)
    return cls(amount, script_pubkey)


class Session3Test(TestCase):

    def test_apply(self):
        S256Point.verify = verify
        PrivateKey.sign = sign
        Tx.parse = parse_tx
        TxIn.parse = parse_txin
        TxOut.parse = parse_txout

    def test_example_1(self):
        secret = 1800555555518005555555
        z = int.from_bytes(hash256(b'ECDSA is awesome!'), 'big')
        k = pow(90210, 99, N)
        r = (k*G).x.num
        s = (z+r*secret) * pow(k, N-2, N) % N
        self.assertEqual(z, 0xcf6304e0ed625dc13713ad8b330ca764325f013fe7a3057dbe6a2053135abeb4)
        self.assertEqual(r, 0x6eb4496bf97ccc36032801586b823d6c4bae7f846b1105e606e522c3aa037c09)
        self.assertEqual(s, 0x65c750dca3dfeb5ba129f846997869f0353ae82eb22050af247c337fd99ae722)
        point = secret * G
        self.assertEqual(point.x.num, 0x4519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574)
        self.assertEqual(point.y.num, 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4)

    def test_example_2(self):
        z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
        r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
        s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
        point = S256Point(
            0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574,
            0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4)
        u = z * pow(s, N-2, N) % N
        v = r * pow(s, N-2, N) % N
        self.assertTrue((u*G + v*point).x.num == r)

    def test_exercise_1(self):
        px = 0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c
        py = 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34
        signatures = (
            (0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
             0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395,
             0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4),
            (0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
             0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c,
             0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6)
        )
        point = S256Point(px, py)
        for z, r, s in signatures:
            u = z * pow(s, N-2, N) % N
            v = r * pow(s, N-2, N) % N
            self.assertTrue((u*G+v*point).x.num == r)

    def test_exercise_2(self):
        der = bytes.fromhex('304402201f62993ee03fca342fcb45929993fa6ee885e00ddad8de154f268d98f083991402201e1ca12ad140c04e0e022c38f7ce31da426b8009d02832f0b44f39a6b178b7a1')
        sec = bytes.fromhex('0204519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574')
        z = int.from_bytes(hash256(b'ECDSA is awesome!'), 'big')
        sig = Signature.parse(der)
        point = S256Point.parse(sec)
        self.assertTrue(point.verify(z, sig))

    def test_exercise_7(self):
        hex_transaction = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600'
        bin_transaction = bytes.fromhex(hex_transaction)
        stream = BytesIO(bin_transaction)
        tx_obj = Tx.parse(stream)
        self.assertEqual(
            tx_obj.tx_ins[1].script_sig.instructions[0].hex(),
            '304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(
            tx_obj.tx_ins[1].script_sig.instructions[1].hex(),
            '035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(tx_obj.tx_outs[0].script_pubkey.instructions[0], 0x76)
        self.assertEqual(tx_obj.tx_outs[0].script_pubkey.instructions[1], 0xa9)
        self.assertEqual(
            tx_obj.tx_outs[0].script_pubkey.instructions[2].hex(),
            'ab0c0b2e98b1ab6dbf67d4750b0a56244948a879')
        self.assertEqual(tx_obj.tx_outs[0].script_pubkey.instructions[3], 0x88)
        self.assertEqual(tx_obj.tx_outs[0].script_pubkey.instructions[4], 0xac)
        self.assertEqual(tx_obj.tx_outs[1].amount, 40000000)
