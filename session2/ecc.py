from unittest import TestCase

from helper import encode_base58_checksum, hash160, hash256


class FieldElement:

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime-1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        # this should be the inverse of the == operator
        return not (self == other)

    def __repr__(self):
        return f'FieldElement_{self.prime}({self.num})'

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        # self.num and other.num are the actual values
        num = (self.num + other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        # self.num and other.num are the actual values
        num = (self.num - other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        # self.num and other.num are the actual values
        num = (self.num * other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __pow__(self, n):
        # self.num is the base, n is the exponent
        # self.prime is what you'll need to mod against
        prime = self.prime
        # use pow(base, exponent, prime) to calculate the number
        num = pow(self.num, n, prime)
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        # self.num and other.num are the actual values
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # use fermat's little theorem:
        # self.num**(p-1) % p == 1
        # this means:
        # 1/n == pow(n, p-2, p)
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


class FieldElementTest(TestCase):

    def test_ne(self):
        a = FieldElement(2, 31)
        b = FieldElement(2, 31)
        c = FieldElement(15, 31)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FieldElement(2, 31)
        b = FieldElement(15, 31)
        self.assertEqual(a + b, FieldElement(17, 31))
        a = FieldElement(17, 31)
        b = FieldElement(21, 31)
        self.assertEqual(a + b, FieldElement(7, 31))

    def test_sub(self):
        a = FieldElement(29, 31)
        b = FieldElement(4, 31)
        self.assertEqual(a - b, FieldElement(25, 31))
        a = FieldElement(15, 31)
        b = FieldElement(30, 31)
        self.assertEqual(a - b, FieldElement(16, 31))

    def test_mul(self):
        a = FieldElement(24, 31)
        b = FieldElement(19, 31)
        self.assertEqual(a * b, FieldElement(22, 31))

    def test_pow(self):
        a = FieldElement(17, 31)
        self.assertEqual(a**3, FieldElement(15, 31))
        a = FieldElement(5, 31)
        b = FieldElement(18, 31)
        self.assertEqual(a**5 * b, FieldElement(16, 31))

    def test_div(self):
        a = FieldElement(3, 31)
        b = FieldElement(24, 31)
        self.assertEqual(a / b, FieldElement(4, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a**-3, FieldElement(29, 31))
        a = FieldElement(4, 31)
        b = FieldElement(11, 31)
        self.assertEqual(a**-4 * b, FieldElement(13, 31))


class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        # x being None and y being None represents the point at infinity
        # Check for that here since the equation below won't make sense
        # with None values for both.
        if self.x is None and self.y is None:
            return
        # make sure that the elliptic curve equation is satisfied
        # y**2 == x**3 + a*x + b
        if self.y**2 != self.x**3 + a * x + b:
            # if not, raise a ValueError
            raise ValueError(f'({self.x}, {self.y}) is not on the curve')

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        # this should be the inverse of the == operator
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return f'Point({self.x.num},{self.y.num})_{self.x.prime}'

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')
        # Case 0.0: self is the point at infinity, return other
        if self.x is None:
            return other
        # Case 0.1: other is the point at infinity, return self
        if other.x is None:
            return self

        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            # Remember to return an instance of this class:
            # self.__class__(x, y, a, b)
            return self.__class__(None, None, self.a, self.b)

        # Case 2: self.x != other.x
        if self.x != other.x:
            # Formula (x3,y3)==(x1,y1)+(x2,y2)
            # s=(y2-y1)/(x2-x1)
            s = (other.y - self.y) / (other.x - self.x)
            # x3=s**2-x1-x2
            x = s**2 - self.x - other.x
            # y3=s*(x1-x3)-y1
            y = s * (self.x - x) - self.y
            # use: self.__class__(x, y, self.a, self.b)
            return self.__class__(x, y, self.a, self.b)

        # Case 3: self == other
        else:
            # Formula (x3,y3)=(x1,y1)+(x1,y1)
            # s=(3*x1**2+a)/(2*y1)
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            # x3=s**2-2*x1
            x = s**2 - 2 * self.x
            # y3=s*(x1-x3)-y1
            y = s * (self.x - x) - self.y
            # use: self.__class__(x, y, self.a, self.b)
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        # rmul calculates coefficient * self
        coef = coefficient
        current = self
        # start at 0
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            # if the bit at this binary expansion is 1, add
            if coef & 1:
                result += current
            # double the point
            current += current
            coef >>= 1
        return result


class PointTest(TestCase):

    def test_ne(self):
        a = Point(x=3, y=-7, a=5, b=7)
        b = Point(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_on_curve(self):
        with self.assertRaises(ValueError):
            Point(x=-2, y=4, a=5, b=7)
        # these should not raise an error
        Point(x=3, y=-7, a=5, b=7)
        Point(x=18, y=77, a=5, b=7)

    def test_add0(self):
        a = Point(x=None, y=None, a=5, b=7)
        b = Point(x=2, y=5, a=5, b=7)
        c = Point(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = Point(x=3, y=7, a=5, b=7)
        b = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = Point(x=-1, y=1, a=5, b=7)
        self.assertEqual(a + a, Point(x=18, y=-77, a=5, b=7))


class ECCTest(TestCase):

    def test_on_curve(self):
        # tests the following points whether they are on the curve or not
        # on curve y^2=x^3-7 over F_223:
        # (192,105) (17,56) (200,119) (1,193) (42,99)
        # the ones that aren't should raise a ValueError
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))

        # iterate over valid points
            # Initialize points this way:
            # x = FieldElement(x_raw, prime)
            # y = FieldElement(y_raw, prime)
            # Point(x, y, a, b)
            # Creating the point should not result in an error

        # iterate over invalid points
            # Initialize points this way:
            # x = FieldElement(x_raw, prime)
            # y = FieldElement(y_raw, prime)
            # Point(x, y, a, b)
            # check that creating the point results in a ValueError
            # use: with self.assertRaises(ValueError):
        raise NotImplementedError

    def test_add(self):
        # tests the following additions on curve y^2=x^3-7 over F_223:
        # (192,105) + (17,56)
        # (47,71) + (117,141)
        # (143,98) + (76,66)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        additions = (
            # (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        )
        # iterate over the additions
            # Initialize points this way:
            # x1 = FieldElement(x1_raw, prime)
            # y1 = FieldElement(y1_raw, prime)
            # p1 = Point(x1, y1, a, b)
            # x2 = FieldElement(x2_raw, prime)
            # y2 = FieldElement(y2_raw, prime)
            # p2 = Point(x2, y2, a, b)
            # x3 = FieldElement(x3_raw, prime)
            # y3 = FieldElement(y3_raw, prime)
            # p3 = Point(x3, y3, a, b)
            # check that p1 + p2 == p3
        raise NotImplementedError

    def test_rmul(self):
        # tests the following scalar multiplications
        # 2*(192,105)
        # 2*(143,98)
        # 2*(47,71)
        # 4*(47,71)
        # 8*(47,71)
        # 21*(47,71)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        multiplications = (
            # (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
            (21, 47, 71, None, None),
        )

        # iterate over the multiplications
            # Initialize points this way:
            # x1 = FieldElement(x1_raw, prime)
            # y1 = FieldElement(y1_raw, prime)
            # p1 = Point(x1, y1, a, b)
            # initialize the second point based on whether it's the point at infinity
            # x2 = FieldElement(x2_raw, prime)
            # y2 = FieldElement(y2_raw, prime)
            # p2 = Point(x2, y2, a, b)
            # check that the product is equal to the expected point
        raise NotImplementedError


A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def hex(self):
        return f'{self.num:x}'.zfill(64)

    def __repr__(self):
        return self.hex()


class S256Point(Point):

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return f'S256Point({self.x.num:x},{self.y.num:x})'

    def __rmul__(self, coefficient):
        # we want to mod by N to make this simple
        coef = coefficient % N
        return super().__rmul__(coef)

    def sec(self, compressed=True):
        # returns the binary version of the sec format, NOT hex
        # if compressed, starts with b'\x02' if self.y.num is even, b'\x03' if self.y is odd
        # then self.x.num
        # remember, you have to convert self.x.num/self.y.num to binary (some_integer.to_bytes(32, 'big'))
            # if non-compressed, starts with b'\x04' followod by self.x and then self.y
        raise NotImplementedError

    def address(self, compressed=True, testnet=False):
        '''Returns the address string'''
        # get the sec
        # hash160 the sec
        # prefix is b'\x00' for mainnet, b'\x6f' for testnet
        # return the encode_base58_checksum of the prefix and h160
        raise NotImplementedError


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class S256Test(TestCase):

    def test_order(self):
        point = N * G
        self.assertIsNone(point.x)

    def test_pubpoint(self):
        # write a test that tests the public point for the following
        points = (
            # secret, x, y
            (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
            (1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
            (2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
            (2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
        )

        # iterate over points
            # initialize the secp256k1 point (S256Point)
            # check that the secret*G is the same as the point
        raise NotImplementedError

    def test_sec(self):
        coefficient = 999**3
        uncompressed = '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9'
        compressed = '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
        coefficient = 123
        uncompressed = '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b'
        compressed = '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5'
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
        coefficient = 42424242
        uncompressed = '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3'
        compressed = '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))

    def test_address(self):
        secret = 888**3
        mainnet_address = '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'
        testnet_address = 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'
        point = secret * G
        self.assertEqual(
            point.address(compressed=True, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=True, testnet=True), testnet_address)
        secret = 321
        mainnet_address = '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj'
        testnet_address = 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP'
        point = secret * G
        self.assertEqual(
            point.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=False, testnet=True), testnet_address)
        secret = 4242424242
        mainnet_address = '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb'
        testnet_address = 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s'
        point = secret * G
        self.assertEqual(
            point.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=False, testnet=True), testnet_address)
