from random import randint
from unittest import TestCase


class Session1Test(TestCase):

    def test_example_1(self):
        self.assertEqual((11 + 6) % 19, 17)
        self.assertEqual((17 - 11) % 19, 6)
        self.assertEqual((8 + 14) % 19, 3)
        self.assertEqual((4 - 12) % 19, 11)

    def test_exercise_1(self):
        prime = 31
        self.assertEqual((2+15) % prime, 17)
        self.assertEqual((17+21) % prime, 7)
        self.assertEqual((29-4) % prime, 25)
        self.assertEqual((15-30) % prime, 16)

    def test_example_2(self):
        self.assertEqual(2 * 4 % 19, 8)
        self.assertEqual(7 * 3 % 19, 2)
        self.assertEqual(11 ** 3 % 19, 1)
        self.assertEqual(pow(11, 3, 19), 1)

    def test_exercise_2_1(self):
        prime = 31
        self.assertEqual(24*19 % prime, 22)
        self.assertEqual(17**3 % prime, 15)
        self.assertEqual(5**5*18 % prime, 16)

    def test_exercise_2_2(self):
        prime = 31
        k = randint(1, prime - 1)
        self.assertEqual(sorted([i*k % prime for i in range(prime)]), [i for i in range(prime)])

    def test_exercise_2_4(self):
        prime = 31
        self.assertEqual([i**30 % prime for i in range(1, prime)], [1] * (prime - 1))

    def test_example_3(self):
        self.assertEqual(2 * 3**17 % 19, 7)
        self.assertEqual(2 * pow(3, 17, 19) % 19, 7)
        self.assertEqual(3 * 15**17 % 19, 4)
        self.assertEqual(3 * pow(15, 17, 19) % 19, 4)

    def test_exercise_3(self):
        prime = 31
        self.assertEqual(3*24**(prime-2) % prime, 4)
        self.assertEqual(pow(17, prime-4, prime), 29)
        self.assertEqual(pow(4, prime-5, prime) * 11 % prime, 13)

    def test_example_4(self):
        x, y = -1, -1
        self.assertTrue(y**2 == x**3 + 5*x + 7)

    def test_exercise_4(self):
        points = ((-2, 4), (3, 7), (18, 77))
        expected = [False, True, True]
        for x, y in points:
            self.assertEqual(y**2 == x**3 + 5*x + 7, expected.pop(0))

    def test_example_5(self):
        x1, y1 = (2, 5)
        x2, y2 = (3, 7)
        s = (y2-y1)/(x2-x1)
        x3 = s**2 - x2 - x1
        y3 = s*(x1-x3)-y1
        self.assertEqual((x3, y3), (-1.0, 1.0))

    def test_exercise_6(self):
        x1, y1 = (2, 5)
        x2, y2 = (-1, -1)
        s = (y2-y1)/(x2-x1)
        x3 = s**2 - x2 - x1
        y3 = s*(x1-x3) - y1
        self.assertEqual((x3, y3), (3.0, -7.0))

    def test_example_6(self):
        a = 5
        x1, y1 = (2, 5)
        s = (3*x1**2+a)/(2*y1)
        x3 = s**2 - 2*x1
        y3 = s*(x1-x3) - y1
        self.assertEqual((x3, y3), (-1.1100000000000003, 0.2870000000000008))

    def test_exercise_7(self):
        a, b = 5, 7
        x1, y1 = -1, -1
        s = (3*x1**2+a)/(2*y1)
        x3 = s**2 - 2*x1
        y3 = s*(x1-x3) - y1
        self.assertEqual((x3, y3), (18.0, 77.0))
