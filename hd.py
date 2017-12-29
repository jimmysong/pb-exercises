import hashlib
import hmac

from binascii import hexlify, unhexlify
from unittest import TestCase

from ecc import S256Point, PrivateKey, N
from helper import raw_decode_base58, encode_base58_checksum, hash160


class HDPrivateKey:

    def __init__(self, private_key, chain_code, depth, fingerprint, child_number):
        self.private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
        self.pub = HDPublicKey(
            point=self.private_key.point,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def xprv(self, testnet=False):
        if testnet:
            version = unhexlify('04358394')
        else:
            version = unhexlify('0488ADE4')
        depth = bytes([self.depth])
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        prv = bytes([0]) + self.private_key.secret.to_bytes(32, 'big')
        to_encode = version + depth + fingerprint + child_number + chain_code + prv
        return encode_base58_checksum(to_encode)

    def xpub(self):
        return self.pub.xpub()
    
    @classmethod
    def from_seed(cls, seed, path):
        raw = hmac.HMAC(key=b'Bitcoin seed', msg=seed, digestmod=hashlib.sha512).digest()
        private_key = PrivateKey(secret=int.from_bytes(raw[:32], 'big'))
        chain_code = raw[32:]
        root = cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=0,
            fingerprint=b'\x00\x00\x00\x00',
            child_number=0,
        )
        return root.traverse(path)

    def traverse(self, path):
        current = self
        for child in path.split(b'/')[1:]:
            current = current.child(int(child))
        return current

    @classmethod
    def parse(cls, xprv):
        num = raw_decode_base58(xprv)
        raw = num.to_bytes(82, 'big')
        version = raw[:4]
        if version == unhexlify('04358394'):
            testnet = True
        elif version == unhexlify('0488ADE4'):
            testnet = False
        else:
            raise RuntimeError('not an xprv: {}'.format(xprv))
        depth = raw[4]
        fingerprint = raw[5:9]
        child_number = int.from_bytes(raw[9:13], 'big')
        chain_code = raw[13:45]
        private_key = PrivateKey(secret=int.from_bytes(raw[46:-4], 'big'))
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def child(self, index):
        sec = self.private_key.point.sec()
        data = sec + index.to_bytes(4, 'big')
        raw = hmac.HMAC(key=self.chain_code, msg=data, digestmod=hashlib.sha512).digest()
        secret = (int.from_bytes(raw[:32], 'big') + self.private_key.secret) % N
        private_key = PrivateKey(secret=secret)
        chain_code = raw[32:]
        depth = self.depth + 1
        fingerprint = hash160(sec)[:4]
        child_number = index
        return HDPrivateKey(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def address(self):
        return self.point.address()


class HDPublicKey:

    def __init__(self, point, chain_code, depth, fingerprint, child_number):
        self.point = point
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number

        
    def xpub(self, testnet=False):
        if testnet:
            version = unhexlify('043587CF')
        else:
            version = unhexlify('0488B21E')
        depth = bytes([self.depth])
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        sec = self.point.sec()
        to_encode = version + depth + fingerprint + child_number + chain_code + sec
        return encode_base58_checksum(to_encode)


    def traverse(self, path):
        current = self
        for child in path.split(b'/')[1:]:
            current = current.child(int(child))
        return current

    @classmethod
    def parse(cls, xpub):
        num = raw_decode_base58(xpub)
        raw = num.to_bytes(82, 'big')
        version = raw[:4]
        if version == unhexlify('043587CF'):
            testnet = True
        elif version == unhexlify('0488B21E'):
            testnet = False
        else:
            raise RuntimeError('not an xpub: {}'.format(xpub))
        depth = raw[4]
        fingerprint = raw[5:9]
        child_number = int.from_bytes(raw[9:13], 'big')
        chain_code = raw[13:45]
        point = S256Point.parse(raw[45:-4])
        return cls(
            point=point,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def child(self, index):
        sec = self.point.sec()
        data = sec + index.to_bytes(4, 'big')
        raw = hmac.HMAC(key=self.chain_code, msg=data, digestmod=hashlib.sha512).digest()
        point = PrivateKey(int.from_bytes(raw[:32], 'big')).point + self.point
        chain_code = raw[32:]
        depth = self.depth + 1
        fingerprint = hash160(sec)[:4]
        child_number = index
        return HDPublicKey(
            point=point,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )


class HDTest(TestCase):
    
    def test_from_seed(self):
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        hd_private_key = HDPrivateKey.from_seed(seed, b'm')
        want = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        self.assertEqual(hd_private_key.xprv(), want)
        hd_private_key = HDPrivateKey.parse(want)
        self.assertEqual(hd_private_key.xprv(), want)
        want = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        self.assertEqual(hd_private_key.xpub(), want)
        hd_public_key = HDPublicKey.parse(want)
        self.assertEqual(hd_public_key.xpub(), want)

        seed = unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
        hd_private_key = HDPrivateKey.from_seed(seed, b'm')
        want = 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
        self.assertEqual(hd_private_key.xprv(), want)
        pub = want = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        self.assertEqual(hd_private_key.xpub(), want)
        hd_private_key = HDPrivateKey.from_seed(seed, b'm/0')
        want = 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
        self.assertEqual(hd_private_key.xprv(), want)
        want = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        self.assertEqual(hd_private_key.xpub(), want)

        hd_public_key = HDPublicKey.parse(pub)
        self.assertEqual(hd_public_key.child(0).xpub(), want)
