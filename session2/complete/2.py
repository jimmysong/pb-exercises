from unittest import TestCase

from ecc import (
    FieldElement,
    G,
    Point,
    S256Point,
)
from helper import (
    encode_base58,
    hash160,
    hash256,
    little_endian_to_int,
)


class Sessios2Test(TestCase):

    def test_example_1(self):
        prime = 137
        x, y = 73, 128
        self.assertTrue(y**2 % prime == (x**3 + 7) % prime)

    def test_exercise_1(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        points = ((192, 105), (17, 56), (200, 119), (1, 193), (42, 99))
        expected = [True, True, False, True, False]
        for x_raw, y_raw in points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            if expected.pop(0):
                self.assertTrue(Point(x, y, a, b))
            else:
                with self.assertRaises(ValueError):
                    Point(x, y, a, b)

    def test_example_2(self):
        prime = 137
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        p1 = Point(FieldElement(73, prime), FieldElement(128, prime), a, b)
        p2 = Point(FieldElement(46, prime), FieldElement(22, prime), a, b)
        p3 = p1 + p2
        self.assertEqual(p3.x.num, 99)
        self.assertEqual(p3.y.num, 49)

    def test_exercise_2(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        additions = ((192, 105, 17, 56), (47, 71, 117, 141), (143, 98, 76, 66))
        expected = [(170, 142), (60, 139), (47, 71)]
        for x1_raw, y1_raw, x2_raw, y2_raw in additions:
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = Point(x1, y1, a, b)
            x2 = FieldElement(x2_raw, prime)
            y2 = FieldElement(y2_raw, prime)
            p2 = Point(x2, y2, a, b)
            p3 = p1 + p2
            self.assertEqual((p3.x.num, p3.y.num), expected.pop(0))

    def test_example_3(self):
        prime = 137
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        p = Point(FieldElement(73, prime), FieldElement(128, prime), a, b)
        p2 = p + p
        self.assertEqual(p2.x.num, 103)
        self.assertEqual(p2.y.num, 76)

    def test_exercise_3(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        multiplications = ((2, 192, 105), (2, 143, 98), (2, 47, 71), (4, 47, 71), (8, 47, 71), (21, 47, 71))
        expected = [(49, 71), (64, 168), (36, 111), (194, 51), (116, 55), None]
        for n, x_raw, y_raw in multiplications:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            p = Point(x, y, a, b)
            product = Point(None, None, a, b)
            for _ in range(n):
                product = product + p
            if product.x is None:
                self.assertEqual(None, expected.pop(0))
            else:
                self.assertEqual((product.x.num, product.y.num), expected.pop(0))

    def test_example_4(self):
        expected = [(47, 71), (36, 111), (15, 137), (194, 51), (126, 96), (139, 137), (92, 47), (116, 55), (69, 86), (154, 150), (154, 73), (69, 137), (116, 168), (92, 176), (139, 86), (126, 127), (194, 172), (15, 86), (36, 112), (47, 152)]
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        g = Point(FieldElement(47, prime), FieldElement(71, prime), a, b)
        inf = Point(None, None, a, b)
        total = g
        count = 1
        while total != inf:
            self.assertEqual((total.x.num, total.y.num), expected.pop(0))
            total += g
            count += 1
        self.assertEqual(total, inf)

    def test_exercise_4(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        x = FieldElement(15, prime)
        y = FieldElement(86, prime)
        p = Point(x, y, a, b)
        inf = Point(None, None, a, b)
        product = p
        counter = 1
        while product != inf:
            product += p
            counter += 1
        self.assertEqual(counter, 7)

    def test_example_5(self):
        p = 2**256 - 2**32 - 977
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.assertTrue(y**2 % p == (x**3 + 7) % p)

    def test_example_6(self):
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        p = n * G
        self.assertEqual(p.x, None)

    def test_example_7(self):
        secret = 999
        point = secret*G
        self.assertEqual(point.x.num, 0x9680241112d370b56da22eb535745d9e314380e568229e09f7241066003bc471)
        self.assertEqual(point.y.num, 0xddac2d377f03c201ffa0419d6596d10327d6c70313bb492ff495f946285d8f38)

    def test_exercise_5(self):
        secrets = (7, 1485, 2**128, 2**240+2**31)
        expected = [
            (0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
            (0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
            (0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
            (0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
        ]
        for secret in secrets:
            p = secret * G
            self.assertEqual((p.x.num, p.y.num), expected.pop(0))

    def test_example_8(self):
        point = S256Point(0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC, 0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA)
        uncompressed = b'\x04' + point.x.num.to_bytes(32, 'big') + point.y.num.to_bytes(32, 'big')
        if point.y.num % 2 == 1:
            compressed = b'\x03' + point.x.num.to_bytes(32, 'big')
        else:
            compressed = b'\x02' + point.x.num.to_bytes(32, 'big')
        self.assertEqual(uncompressed.hex(), '045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da')
        self.assertEqual(compressed.hex(), '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc')

    def test_exercise_6(self):
        secrets = (999**3, 123, 42424242)
        expected = [('049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9', '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'), ('04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b', '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5'), ('04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3', '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e')]
        for secret in secrets:
            point = secret * G
            uncompressed = b'\x04' + point.x.num.to_bytes(32, 'big') + point.y.num.to_bytes(32, 'big')
            if point.y.num % 2 == 1:
                compressed = b'\x03' + point.x.num.to_bytes(32, 'big')
            else:
                compressed = b'\x02' + point.x.num.to_bytes(32, 'big')
            self.assertEqual((uncompressed.hex(), compressed.hex()), expected.pop(0))

    def test_example_9(self):
        sec = bytes.fromhex('025CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC')
        h160 = hash160(sec)
        raw = b"\x00" + h160
        raw = raw + hash256(raw)[:4]
        addr = encode_base58(raw)
        self.assertEqual(addr, b'19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA')

    def test_exercise_7(self):
        components = (
            (888**3, True),
            (321, False),
            (4242424242, False),
        )
        expected = [
            '148dY81A9BmdpMhvYEVznrM45kWN32vSCN',
            'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP',
            '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj',
            'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP',
            '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb',
            'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s',
        ]
        for secret, compressed in components:
            point = secret * G
            sec = point.sec(compressed)
            h160 = hash160(sec)
            for prefix in (b'\x00', b'\x6f'):
                raw = prefix + h160
                checksum = hash256(raw)[:4]
                total = raw + checksum
                self.assertEqual(encode_base58(total).decode('ascii'), expected.pop(0))

    def test_exercise_8(self):
        passphrase = b'Jimmy Song Programming Blockchain'
        secret = little_endian_to_int(hash256(passphrase))
        point = secret*G
        self.assertEqual(point.address(testnet=True), 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv')
