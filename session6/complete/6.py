from io import BytesIO
from unittest import TestCase

from block import Block
from helper import (
    hash256,
    little_endian_to_int,
)
from script import Script
from tx import Tx


class Session6Test(TestCase):

    def test_exercise_2(self):
        hex_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'
        stream = BytesIO(bytes.fromhex(hex_tx))
        coinbase = Tx.parse(stream)
        self.assertEqual(coinbase.tx_ins[0].script_sig.instructions[2], b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')

    def test_exercise_3(self):
        hex_script_pubkey = '1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac'
        stream = BytesIO(bytes.fromhex(hex_script_pubkey))
        script_pubkey = Script.parse(stream)
        self.assertEqual(script_pubkey.address(), '15hZo812Lx266Dot6T52krxpnhrNiaqHya')

    def test_exercise_4(self):
        hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
        bin_block = bytes.fromhex(hex_block)
        result = hash256(bin_block)
        self.assertEqual(result.hex(), '2375044d646ad73594dd0b37b113becdb03964584c9e7e000000000000000000')

    def test_example_1(self):
        hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
        bin_block = bytes.fromhex(hex_block)
        stream = BytesIO(bin_block)
        b = Block.parse(stream)
        version = b.version
        self.assertTrue(version >> 29 == 0b001)
        self.assertFalse(version >> 4 & 1 == 1)
        self.assertTrue(version >> 1 & 1 == 1)

    def test_example_2(self):
        bits = bytes.fromhex('e93c0118')
        exponent = bits[-1]
        coefficient = little_endian_to_int(bits[:-1])
        target = coefficient * 256**(exponent - 3)
        self.assertEqual('{:x}'.format(target).zfill(64), '0000000000000000013ce9000000000000000000000000000000000000000000')

    def test_example_3(self):
        bits = bytes.fromhex('e93c0118')
        exponent = bits[-1]
        coefficient = little_endian_to_int(bits[:-1])
        target = coefficient * 256**(exponent - 3)
        min_target = 0xffff * 256**(0x1d - 3)
        difficulty = min_target // target
        self.assertEqual(difficulty, 888171856257)

    def test_exercise_6(self):
        hex_bits = 'f2881718'
        bits = bytes.fromhex(hex_bits)
        exponent = bits[-1]
        coefficient = little_endian_to_int(bits[:-1])
        target = coefficient * 256**(exponent - 3)
        self.assertEqual('{:x}'.format(target).zfill(64), '00000000000000001788f2000000000000000000000000000000000000000000')
        difficulty = 0xffff * 256**(0x1d - 3) // target
        self.assertEqual(difficulty, 46717549644)

    def test_exercise_7(self):
        hex_block = '04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1'
        bin_block = bytes.fromhex(hex_block)
        stream = BytesIO(bin_block)
        b = Block.parse(stream)
        h256 = hash256(b.serialize())
        proof = little_endian_to_int(h256)
        target = b.target()
        self.assertTrue(proof < target)
