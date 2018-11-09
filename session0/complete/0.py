from unittest import TestCase


class Session0Test(TestCase):

    def test_example_2(self):

        def fib(n):
            if n in (0, 1):
                return 1
            else:
                return fib(n-1) + fib(n-2)

        self.assertEqual(fib(10), 89)
        self.assertEqual(fib(20), 10946)

    def test_example_3(self):
        s = 'hello world'
        b = b'hello world'
        self.assertFalse(s == b)
        hello_world_bytes = s.encode('ascii')
        self.assertTrue(hello_world_bytes == b)
        hello_world_string = b.decode('ascii')
        self.assertTrue(hello_world_string == s)

    def test_example_6(self):
        a = [1, 2, 3, 4, 5]
        self.assertEqual(a[::-1], [5, 4, 3, 2, 1])
        s = 'hello world'
        self.assertEqual(s[::-1], 'dlrow olleh')
        b = b'hello world'
        self.assertEqual(b[::-1], b'dlrow olleh')
        self.assertEqual(b'&'[0], 38)
        self.assertEqual(bytes([38]), b'&')

    def test_example_7(self):
        b = b'hello world'
        h = '68656c6c6f20776f726c64'
        self.assertEqual(b.hex(), h)
        self.assertEqual(bytes.fromhex(h), b)

    def test_exercise_2(self):
        h = 'b010a49c82b4bc84cc1dfd6e09b2b8114d016041efaf591eca88959e327dd29a'
        b = bytes.fromhex(h)
        b_rev = b[::-1]
        h_rev = b_rev.hex()
        want = '9ad27d329e9588ca1e59afef4160014d11b8b2096efd1dcc84bcb4829ca410b0'
        self.assertEqual(h_rev, want)

    def test_exercise_3(self):
        prime = 19
        self.assertEqual(99 % prime, 4)
        self.assertEqual(456*444 % prime, 0)
        self.assertEqual(9**77 % prime, 16)

    def test_example_9(self):
        n = 1234567890
        big_endian = n.to_bytes(4, 'big')
        little_endian = n.to_bytes(4, 'little')
        self.assertEqual(big_endian.hex(), '499602d2')
        self.assertEqual(little_endian.hex(), 'd2029649')
        self.assertEqual(int.from_bytes(big_endian, 'big'), n)
        self.assertEqual(int.from_bytes(little_endian, 'little'), n)

    def test_exercise_4(self):
        n = 8675309
        self.assertEqual(n.to_bytes(8, 'big').hex(), '0000000000845fed')
        little_endian = b'\x11\x22\x33\x44\x55'
        self.assertEqual(int.from_bytes(little_endian, 'little'), 366216421905)
