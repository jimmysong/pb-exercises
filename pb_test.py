from random import randint
from unittest import TestCase

from pb import FieldElement, Point, G, N, PrivateKey


class FieldElementTest(TestCase):

    def test_add(self):
        a = FieldElement(2, 31)
        b = FieldElement(15, 31)
        self.assertEqual(a+b, FieldElement(17, 31))
        a = FieldElement(17, 31)
        b = FieldElement(21, 31)
        self.assertEqual(a+b, FieldElement(7, 31))

    def test_sub(self):
        a = FieldElement(29, 31)
        b = FieldElement(4, 31)
        self.assertEqual(a-b, FieldElement(25, 31))
        a = FieldElement(15, 31)
        b = FieldElement(30, 31)
        self.assertEqual(a-b, FieldElement(16, 31))

    def test_mul(self):
        a = FieldElement(24, 31)
        b = FieldElement(19, 31)
        self.assertEqual(a*b, FieldElement(22, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a**3, FieldElement(15, 31))
        a = FieldElement(5, 31)
        b = FieldElement(18, 31)
        self.assertEqual(a**5 * b, FieldElement(16, 31))

    def test_div(self):
        a = FieldElement(3, 31)
        b = FieldElement(24, 31)
        self.assertEqual(a/b, FieldElement(4, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a**-3, FieldElement(29, 31))
        a = FieldElement(4, 31)
        b = FieldElement(11, 31)
        self.assertEqual(a**-4*b, FieldElement(13, 31))


class PointTest(TestCase):

    def test_add1(self):
        a = Point(3, 7, 5, 7)
        b = Point(2, 5, 5, 7)
        self.assertEqual(a+b, Point(-1, 1, 5, 7))

    def test_add2(self):
        a = Point(-1, 1, 5, 7)
        self.assertEqual(a+a, Point(18, -77, 5, 7))


class ECCTest(TestCase):

    def test_on_curve(self):
        self.assertTrue(Point(FieldElement(192, 223), FieldElement(105, 223)))
        self.assertTrue(Point(FieldElement(17, 223), FieldElement(56, 223)))
        self.assertTrue(Point(FieldElement(1, 223), FieldElement(193, 223)))

    def test_not_on_curve(self):
        with self.assertRaises(RuntimeError):
            Point(FieldElement(200, 223), FieldElement(119, 223))
        with self.assertRaises(RuntimeError):
            Point(FieldElement(42, 223), FieldElement(99, 223))

    def test_add(self):
        a = Point(FieldElement(192, 223), FieldElement(105, 223))
        b = Point(FieldElement(17, 223), FieldElement(56, 223))
        self.assertEqual(
            a+b, Point(FieldElement(170, 223), FieldElement(142, 223)))
        a = Point(FieldElement(47, 223), FieldElement(71, 223))
        b = Point(FieldElement(117, 223), FieldElement(141, 223))
        self.assertEqual(
            a+b, Point(FieldElement(60, 223), FieldElement(139, 223)))
        a = Point(FieldElement(143, 223), FieldElement(98, 223))
        b = Point(FieldElement(76, 223), FieldElement(66, 223))
        self.assertEqual(
            a+b, Point(FieldElement(47, 223), FieldElement(71, 223)))

    def test_mul(self):
        a = Point(FieldElement(192, 223), FieldElement(105, 223))
        self.assertEqual(
            2*a, Point(FieldElement(49, 223), FieldElement(71, 223)))
        a = Point(FieldElement(143, 223), FieldElement(98, 223))
        self.assertEqual(
            2*a, Point(FieldElement(64, 223), FieldElement(168, 223)))
        a = Point(FieldElement(47, 223), FieldElement(71, 223))
        self.assertEqual(
            2*a, Point(FieldElement(36, 223), FieldElement(111, 223)))
        self.assertEqual(
            4*a, Point(FieldElement(194, 223), FieldElement(51, 223)))
        self.assertEqual(
            8*a, Point(FieldElement(116, 223), FieldElement(55, 223)))
        self.assertEqual(21*a, Point(None, None))

    def test_group(self):
        a = Point(FieldElement(15, 223), FieldElement(86, 223))
        self.assertEqual(7*a, Point(None, None))

    def test_order(self):
        secret = 7
        self.assertEqual(secret*G, Point(
            FieldElement(0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC),
            FieldElement(0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA))
        )
        secret = 1485
        self.assertEqual(secret*G, Point(
            FieldElement(0xC982196A7466FBBBB0E27A940B6AF926C1A74D5AD07128C82824A11B5398AFDA),
            FieldElement(0x7A91F9EAE64438AFB9CE6448A1C133DB2D8FB9254E4546B6F001637D50901F55))
        )
        secret = 2**128
        self.assertEqual(secret*G, Point(
            FieldElement(0x8F68B9D2F63B5F339239C1AD981F162EE88C5678723EA3351B7B444C9EC4C0DA),
            FieldElement(0x662A9F2DBA063986DE1D90C2B6BE215DBBEA2CFE95510BFDF23CBF79501FFF82))
        )
        secret = 2**240+2**31
        self.assertEqual(secret*G, Point(
            FieldElement(0x9577FF57C8234558F293DF502CA4F09CBC65A6572C842B39B366F21717945116),
            FieldElement(0x10B49C67FA9365AD7B90DAB070BE339A1DAF9052373EC30FFAE4F72D5E66D053))
        )

    def test_sec(self):
        point = 999**3*G
        self.assertEqual(point.sec(False), "049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9")
        self.assertEqual(point.sec(True), "039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5")
        point = 123*G
        self.assertEqual(point.sec(False), "04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b")
        self.assertEqual(point.sec(True), "03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5")
        point = 42424242*G
        self.assertEqual(point.sec(False), "04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3")
        self.assertEqual(point.sec(True), "03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e")

    def test_address(self):
        point = 888**3*G
        self.assertEqual(
            point.address(compressed=True, testnet=False),
            "148dY81A9BmdpMhvYEVznrM45kWN32vSCN")
        self.assertEqual(
            point.address(compressed=True, testnet=True),
            "mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP")
        point = 321*G
        self.assertEqual(
            point.address(compressed=False, testnet=False),
            "1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj")
        self.assertEqual(
            point.address(compressed=False, testnet=True),
            "mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP")
        point = 4242424242*G
        self.assertEqual(
            point.address(compressed=False, testnet=False),
            "1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb")
        self.assertEqual(
            point.address(compressed=False, testnet=True),
            "mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s")

    def test_verify(self):
        point = Point(
            FieldElement(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c),
            FieldElement(0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34))
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(point.verify(z, r, s))
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(point.verify(z, r, s))


class PrivateKeyTest(TestCase):

    def test_sign(self):
        secret = randint(0, 2**256)
        priv = PrivateKey(secret)
        z = randint(0, 2**256)
        r, s = priv.sign(z)
        self.assertTrue(priv.point.verify(z, r, s))

    def test_wif(self):
        priv = PrivateKey(2**256 - 2**199)
        self.assertEqual(
            priv.wif(compressed=True, testnet=False),
            "L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC")
        priv = PrivateKey(2**256 - 2**201)
        self.assertEqual(
            priv.wif(compressed=False, testnet=True),
            "93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn")
        priv = PrivateKey(
            0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d)
        self.assertEqual(
            priv.wif(compressed=False, testnet=False),
            "5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty")
        priv = PrivateKey(
            0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f)
        self.assertEqual(
            priv.wif(compressed=True, testnet=True),
            "cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg")
