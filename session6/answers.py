'''
#code
>>> import block, tx

#endcode
#unittest
tx:TxTest:test_is_coinbase:
#endunittest
#exercise
Parse the Genesis Block Coinbase Transaction and print out the scriptSig's third item

```
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
```
---
>>> from io import BytesIO
>>> from tx import Tx
>>> hex_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'
>>> # create stream with BytesIO and bytes.fromhex
>>> stream = BytesIO(bytes.fromhex(hex_tx))  #/
>>> # parse the coinbase transaction
>>> coinbase = Tx.parse(stream)  #/
>>> # print the first input's script_sig's third command
>>> print(coinbase.tx_ins[0].script_sig.commands[2])  #/
b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'

#endexercise
#unittest
tx:TxTest:test_coinbase_height:
#endunittest
#exercise
Find the output address corresponding to this ScriptPubKey
```
1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac
```

Remember the structure of pay-to-pubkey-hash (p2pkh) which has `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`.

You need to grab the hash160 and turn that into an address.
---
>>> from io import BytesIO
>>> from script import Script
>>> hex_script_pubkey = '1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac'
>>> # BytesIO(bytes.fromhex) to get the stream
>>> stream = BytesIO(bytes.fromhex(hex_script_pubkey))  #/
>>> # parse with Script
>>> script_pubkey = Script.parse(stream)  #/
>>> # get the address using address() on the script_pubkey
>>> print(script_pubkey.address())  #/
15hZo812Lx266Dot6T52krxpnhrNiaqHya

#endexercise
#exercise
What is the hash256 of this block? Notice anything?
```
020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d
```
---
>>> from helper import hash256
>>> hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
>>> # bytes.fromhex to get the binary
>>> bin_block = bytes.fromhex(hex_block)  #/
>>> # hash256 the result
>>> result = hash256(bin_block)  #/
>>> # hex() to see what it looks like
>>> print(result.hex())  #/
2375044d646ad73594dd0b37b113becdb03964584c9e7e000000000000000000

#endexercise
#unittest
block:BlockTest:test_parse:
#endunittest
#unittest
block:BlockTest:test_serialize:
#endunittest
#unittest
block:BlockTest:test_hash:
#endunittest
#code
>>> # Version Signaling Example
>>> from block import Block
>>> from io import BytesIO
>>> hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
>>> bin_block = bytes.fromhex(hex_block)
>>> stream = BytesIO(bin_block)
>>> b = Block.parse(stream)
>>> version = b.version
>>> print(f'BIP9: {version >> 29 == 0b001}')
BIP9: True
>>> print(f'BIP112: {version >> 0 & 1 == 1}')
BIP112: False
>>> print(f'BIP141: {version >> 1 & 1 == 1}')
BIP141: True
>>> print(f'BIP341: {version >> 2 & 1 == 1}')
BIP341: False
>>> print(f'BIP91: {version >> 4 & 1 == 1}')
BIP91: False

#endcode
#unittest
block:BlockTest:test_bip9:
#endunittest
#unittest
block:BlockTest:test_bip112:
#endunittest
#unittest
block:BlockTest:test_bip141:
#endunittest
#unittest
block:BlockTest:test_bip341:
#endunittest
#unittest
block:BlockTest:test_bip91:
#endunittest
#code
>>> # Calculating Target from Bits Example
>>> from helper import little_endian_to_int
>>> bits = bytes.fromhex('e93c0118')
>>> exponent = bits[-1]
>>> coefficient = little_endian_to_int(bits[:-1])
>>> target = coefficient*256**(exponent-3)
>>> print(f'{target:x}'.zfill(64))
0000000000000000013ce9000000000000000000000000000000000000000000

#endcode
#code
>>> # Calculating Difficulty from Target Example
>>> from helper import little_endian_to_int
>>> bits = bytes.fromhex('e93c0118')
>>> exponent = bits[-1]
>>> coefficient = little_endian_to_int(bits[:-1])
>>> target = coefficient * 256**(exponent - 3)
>>> min_target = 0xffff * 256**(0x1d - 3)
>>> difficulty = min_target // target
>>> print(difficulty)
888171856257

#endcode
#exercise
Calculate the target and difficulty for these bits:
```
f2881718
```

Bits to target formula is

\\(\texttt{coefficient}\cdot256^{(\texttt{exponent}-3)}\\)

where coefficient is the first three bytes in little endian and exponent is the last byte.

Target to Difficulty formula is

\\(\texttt{difficulty} = \texttt{min} / \texttt{target}\\)

where \\(\texttt{min} = \texttt{0xffff}\cdot256^{(\texttt{0x1d}-3)}\\)
---
>>> from helper import little_endian_to_int
>>> hex_bits = 'f2881718'
>>> # bytes.fromhex to get the bits
>>> bits = bytes.fromhex(hex_bits)  #/
>>> # last byte is exponent
>>> exponent = bits[-1]  #/
>>> # first three bytes are the coefficient in little endian
>>> coefficient = little_endian_to_int(bits[:-1])  #/
>>> # plug into formula coefficient * 256^(exponent-3) to get the target
>>> target = coefficient * 256**(exponent-3)  #/
>>> # print target using print(f'{target:x}'.zfill(64))
>>> print(f'{target:x}'.zfill(64))  #/
00000000000000001788f2000000000000000000000000000000000000000000
>>> # difficulty formula is 0xffff * 256**(0x1d - 3) / target
>>> difficulty = 0xffff * 256**(0x1d - 3) // target  #/
>>> # print the difficulty
>>> print(difficulty)  #/
46717549644

#endexercise
#unittest
block:BlockTest:test_target:
#endunittest
#exercise
Validate the proof-of-work for this block
```
04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1
```

Check that the proof-of-work (hash256 interpreted as a little-endian number) is lower than the target.
---
>>> from io import BytesIO
>>> from block import Block
>>> hex_block = '04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1'
>>> # bytes.fromhex to get the binary block
>>> bin_block = bytes.fromhex(hex_block)  #/
>>> # make a stream using BytesIO
>>> stream = BytesIO(bin_block)  #/
>>> # parse the Block
>>> block_obj = Block.parse(stream)  #/
>>> # hash256 the serialization
>>> h256 = hash256(block_obj.serialize())  #/
>>> # interpret the result as a number in little endian
>>> proof = little_endian_to_int(h256)  #/
>>> # get the target
>>> target = block_obj.target()  #/
>>> # check proof of work < target
>>> print(proof < target)  #/
True

#endexercise
#unittest
block:BlockTest:test_check_pow:
#endunittest
#exercise

Calculate the new bits given the first and last blocks of this 2,016-block difficulty adjustment period:

Block 471744:

```
000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3
```

Block 473759:

```
02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474
```
---
>>> from io import BytesIO
>>> from block import Block, TWO_WEEKS, MAX_TARGET
>>> from helper import target_to_bits
>>> block1_hex = '000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3'
>>> block2_hex = '02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474'
>>> last_block = Block.parse(BytesIO(bytes.fromhex(block1_hex)))
>>> first_block = Block.parse(BytesIO(bytes.fromhex(block2_hex)))
>>> # calculate the differential in time between the two blocks
>>> time_differential = last_block.timestamp - first_block.timestamp  #/
>>> # max differential is 4 * TWO_WEEKS
>>> if time_differential > TWO_WEEKS * 4:  #/
...     time_differential = TWO_WEEKS * 4  #/
>>> # min differential is TWO_WEEKS // 4
>>> if time_differential < TWO_WEEKS // 4:  #/
...     time_differential = TWO_WEEKS // 4  #/
>>> # formula for new target is target * time differential // TWO_WEEKS
>>> new_target = last_block.target() * time_differential // TWO_WEEKS  #/
>>> # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
>>> if new_target > MAX_TARGET:  #/
...     new_target = MAX_TARGET  #/
>>> # convert the target to bits
>>> new_bits = target_to_bits(new_target)  #/
>>> # print the new bits in hex
>>> print(new_bits.hex())  #/
80df6217

#endexercise
#unittest
block:BlockTest:test_new_bits:
#endunittest
'''


from unittest import TestCase

from block import Block, MAX_TARGET, TWO_WEEKS
from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    target_to_bits,
)
from tx import Tx


def is_coinbase(self):
    if len(self.tx_ins) != 1:
        return False
    first_input = self.tx_ins[0]
    if first_input.prev_tx != b'\x00' * 32:
        return False
    if first_input.prev_index != 0xffffffff:
        return False
    return True


def coinbase_height(self):
    if not self.is_coinbase():
        return None
    first_input = self.tx_ins[0]
    first_element = first_input.script_sig.commands[0]
    return little_endian_to_int(first_element)


@classmethod
def parse(cls, s):
    version = little_endian_to_int(s.read(4))
    prev_block = s.read(32)[::-1]
    merkle_root = s.read(32)[::-1]
    timestamp = little_endian_to_int(s.read(4))
    bits = s.read(4)
    nonce = s.read(4)
    return cls(version, prev_block, merkle_root, timestamp, bits, nonce)


def serialize(self):
    result = int_to_little_endian(self.version, 4)
    result += self.prev_block[::-1]
    result += self.merkle_root[::-1]
    result += int_to_little_endian(self.timestamp, 4)
    result += self.bits
    result += self.nonce
    return result


def hash(self):
    s = self.serialize()
    h256 = hash256(s)
    return h256[::-1]


def bip9(self):
    return self.version >> 29 == 0b001


def bip112(self):
    return self.version >> 0 & 1 == 1


def bip141(self):
    return self.version >> 1 & 1 == 1


def bip341(self):
    return self.version >> 2 & 1 == 1


def bip91(self):
    return self.version >> 4 & 1 == 1


def target(self):
    exponent = self.bits[-1]
    coefficient = little_endian_to_int(self.bits[:-1])
    return coefficient * 256**(exponent - 3)


def difficulty(self):
    return MAX_TARGET / self.target()


def check_pow(self):
    h256 = hash256(self.serialize())
    proof = little_endian_to_int(h256)
    return proof < self.target()


def new_bits(self, beginning_block):
    time_differential = self.timestamp - beginning_block.timestamp
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = self.target() * time_differential // TWO_WEEKS
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    return target_to_bits(new_target)


class Session6Test(TestCase):

    def test_apply(self):
        Tx.is_coinbase = is_coinbase
        Tx.coinbase_height = coinbase_height
        Block.parse = parse
        Block.serialize = serialize
        Block.hash = hash
        Block.bip9 = bip9
        Block.bip112 = bip112
        Block.bip141 = bip141
        Block.bip341 = bip341
        Block.bip91 = bip91
        Block.target = target
        Block.difficulty = difficulty
        Block.check_pow = check_pow
        Block.new_bits = new_bits
