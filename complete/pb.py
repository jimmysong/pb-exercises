from binascii import hexlify, unhexlify
from hashlib import sha256
from random import randint

from pycoin.encoding import b2a_base58, b2a_hashed_base58, hash160

A = 0
B = 7
P = 2**256-2**32-977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
BITS = 256


class FieldElement:

    def __init__(self, num, prime=P):
        self.num = num
        self.prime = prime
        if self.num >= self.prime or self.num < 0:
            error = "Num {} not in field range 0 to {}".format(
                self.num, self.prime-1)
            raise RuntimeError(error)

    def __eq__(self, other):
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return self.num != other.num or self.prime != other.prime

    def __add__(self, other):
        return FieldElement((self.num + other.num) % self.prime, self.prime)

    def __sub__(self, other):
        return FieldElement((self.num - other.num) % self.prime, self.prime)

    def __mul__(self, other):
        return FieldElement((self.num * other.num) % self.prime, self.prime)

    def __pow__(self, n):
        n = n % (self.prime - 1)
        return FieldElement(pow(self.num, n, self.prime), self.prime)

    def __truediv__(self, other):
        return FieldElement(
            self.num * pow(other.num, self.prime - 2, self.prime) % self.prime,
            self.prime)

    def __repr__(self):
        return "FieldElement_{}({})".format(self.prime, self.num)

    def hex(self):
        return "{:x}".format(self.num).zfill(64)


class Point:

    def __init__(self, x, y, a=FieldElement(A), b=FieldElement(B)):
        self.a = a
        self.b = b
        if x is None and y is None:
            # point at infinity
            self.x = None
            self.y = None
            return
        if y**2 != x**3 + self.a * x + self.b:
            raise RuntimeError("Not a point on the curve")
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y \
            or self.a != other.a or self.b != other.b

    def __add__(self, other):
        # identity
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x:
            if self.y != other.y:
                # point at infinity
                return Point(None, None)
            if type(self.x) == int:
                two = 2
                three = 3
            else:
                two = FieldElement(2, self.x.prime)
                three = FieldElement(3, self.y.prime)
            s = (three * self.x**2 + self.a) / (two * self.y)
            x = s**2 - two * self.x
            y = s * (self.x - x) - self.y
            return Point(x, y, self.a, self.b)
        else:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return Point(x, y, self.a, self.b)

    def __rmul__(self, n):
        # binary expansion
        current = self
        result = Point(None, None)
        for _ in range(BITS):
            if n & 1:
                result += current
            current += current
            n >>= 1
        return result

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return "Point({},{})".format(self.x, self.y)

    def sec(self, compressed=True):
        if compressed:
            if self.y.num & 1:
                prefix = "03"
            else:
                prefix = "02"
            return "{}{}".format(prefix, self.x.hex())
        else:
            return "04{}{}".format(self.x.hex(), self.y.hex())

    def address(self, compressed=True, testnet=False):
        sec_hex = self.sec(compressed)
        sec = unhexlify(self.sec(compressed))
        h160 = hash160(sec)
        if testnet:
            prefix = b"\x6f"
        else:
            prefix = b"\x00"
        raw = prefix + h160
        final = raw + sha256(sha256(raw).digest()).digest()[:4]
        return b2a_base58(final)

    def verify(self, z, r, s):
        u = z * pow(s, N-2, N) % N
        v = r * pow(s, N-2, N) % N
        point = u*G + v*self
        return point.x.num == r

G = Point(FieldElement(Gx), FieldElement(Gy))


class PrivateKey:

    def __init__(self, s):
        self.s = s
        self.point = s*G

    def hex(self):
        return "{:x}".format(self.s).zfill(64)

    def sign(self, z):
        k = randint(0, 2**256)
        k_point = k*G
        r = k_point.x.num
        s = (z + r*self.s) * pow(k, N-2, N) % N
        return r, s

    def wif(self, compressed=True, testnet=False):
        s = unhexlify(self.hex())
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        return b2a_hashed_base58(prefix + s + suffix)
