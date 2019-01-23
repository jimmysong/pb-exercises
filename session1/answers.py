'''
#code
>>> import ecc, helper
>>> from random import randint

#endcode
#code
>>> # Addition/Subtraction example
>>> print((11 + 6) % 19)
17
>>> print((17 - 11) % 19)
6
>>> print((8 + 14) % 19)
3
>>> print((4 - 12) % 19)
11

#endcode
#exercise
Solve these equations in \\(F_{31}\\):
* \\(2+15=?\\)
* \\(17+21=?\\)
* \\(29-4=?\\)
* \\(15-30=?\\)

Remember the % operator does the actual modulo operation. Also remember that `+` and `-` need to be in `()` because in the order of operations `%` comes before `+` and `-`.
---
>>> # remember that % is the modulo operator
>>> prime = 31
>>> # 2+15=?
>>> print((2+15) % prime)  #/
17
>>> # 17+21=?
>>> print((17+21) % prime)  #/
7
>>> # 29-4=?
>>> print((29-4) % prime)  #/
25
>>> # 15-30=?
>>> print((15-30) % prime)  #/
16

#endexercise
#unittest
ecc:FieldElementTest:test_add:
#endunittest
#unittest
ecc:FieldElementTest:test_sub:
#endunittest
#code
>>> # Multiplication/Exponentiation Example
>>> print(2 * 4 % 19)
8
>>> print(7 * 3 % 19)
2
>>> print(11 ** 3 % 19)
1
>>> print(pow(11, 3, 19))
1

#endcode
#exercise
Solve these equations in \\(F_{31}\\):
* \\(24\cdot19=?\\)
* \\(17^3=?\\)
* \\(5^5\cdot18=?\\)
---
>>> # remember that ** is the exponentiation operator
>>> prime = 31
>>> # 24*19=?
>>> print(24*19 % prime)  #/
22
>>> # 17^3=?
>>> print(17**3 % prime)  #/
15
>>> # 5^5*18=?
>>> print(5**5*18 % prime)  #/
16

#endexercise
#exercise
Write a program to calculate \\(0\cdot k, 1\cdot k, 2\cdot k, 3\cdot k, ... 30\cdot k\\) for some \\(k\\) in \\(F_{31}\\).  Notice anything about these sets?
---
>>> from random import randint
>>> prime = 31
>>> k = randint(1,prime)
>>> # use range(prime) to iterate over all numbers from 0 to 30 inclusive
>>> print(sorted([i*k % prime for i in range(prime)]))  #/
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]

#endexercise
#unittest
ecc:FieldElementTest:test_mul:
#endunittest
#unittest
ecc:FieldElementTest:test_pow:
#endunittest
#exercise
#### BONUS QUESTION, ONLY ATTEMPT IF YOU HAVE TIME
Write a program to calculate \\(k^{30}\\) for all k in \\(F_{31}\\). Notice anything?
---
>>> # Bonus
>>> prime = 31
>>> # use range(1, prime) to iterate over all numbers from 1 to 30 inclusive
>>> print([i**30 % prime for i in range(1, prime)])  #/
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

#endexercise
#code
>>> # Division Example
>>> print(2 * 3**17 % 19)
7
>>> print(2 * pow(3, 17, 19) % 19)
7
>>> print(3 * 15**17 % 19)
4
>>> print(3 * pow(15, 17, 19) % 19)
4

#endcode
#exercise
Solve these equations in \\(F_{31}\\):
* \\(3/24 = ?\\)
* \\(17^{-3} = ?\\)
* \\(4^{-4}\cdot{11} = ?\\)
---
>>> # remember pow(x, p-2, p) is the same as 1/x in F_p
>>> prime = 31
>>> # 3/24 = ?
>>> print(3*24**(prime-2) % prime)  #/
4
>>> # 17^(-3) = ?
>>> print(pow(17, prime-4, prime))  #/
29
>>> # 4^(-4)*11 = ?
>>> print(pow(4, prime-5, prime) * 11 % prime)  #/
13

#endexercise
#unittest
ecc:FieldElementTest:test_div:
Hint: the `__pow__` method needs a positive number for the exponent. You can mod by p-1
#endunittest
#code
>>> # Elliptic Curve Example
>>> x, y = -1, -1
>>> print(y**2 == x**3 + 5*x + 7)
True

#endcode
#exercise
For the curve \\(y^2 = x^3 + 5x + 7\\), which of these points are on the curve?
\\((-2,4), (3,7), (18,77)\\)
---
>>> # (-2,4), (3,7), (18,77)
>>> # equation in python is: y**2 == x**3 + 5*x + 7
>>> points = ((-2,4), (3,7), (18,77))
>>> for x, y in points:
...     # determine whether (x,y) is on the curve
...     if y**2 == x**3 + 5*x + 7:  #/
...         print('({},{}) is on the curve'.format(x,y))  #/
...     else:  #/
...         print('({},{}) is not on the curve'.format(x,y))  #/
(-2,4) is not on the curve
(3,7) is on the curve
(18,77) is on the curve

#endexercise
#unittest
ecc:PointTest:test_on_curve:
#endunittest
#unittest
ecc:PointTest:test_add0:
#endunittest
#code
>>> # Point Addition where x1 != x2 Example
>>> x1, y1 = (2, 5)
>>> x2, y2 = (3, 7)
>>> s = (y2-y1)/(x2-x1)
>>> x3 = s**2 - x2 - x1
>>> y3 = s*(x1-x3)-y1
>>> print(x3, y3)
-1.0 1.0

#endcode
#exercise
For the curve \\(y^2 = x^3 + 5x + 7\\), what is \\((2,5) + (-1,-1)\\)?
---
>>> x1, y1 = (2,5)
>>> x2, y2 = (-1,-1)
>>> # formula in python:
>>> # s = (y2-y1)/(x2-x1)
>>> s = (y2-y1)/(x2-x1)  #/
>>> # x3 = s**2 - x2 - x1
>>> x3 = s**2 - x2 - x1  #/
>>> # y3 = s*(x1-x3)-y1
>>> y3 = s*(x1-x3) - y1  #/
>>> # print the coordinates
>>> print(x3, y3)  #/
3.0 -7.0

#endexercise
#unittest
ecc:PointTest:test_add1:
#endunittest
#code
>>> # Point Addition where x1 = x2 Example
>>> a = 5
>>> x1, y1 = (2, 5)
>>> s = (3*x1**2+a)/(2*y1)
>>> x3 = s**2 - 2*x1
>>> y3 = s*(x1-x3) - y1
>>> print(x3, y3)
-1.1100000000000003 0.2870000000000008

#endcode
#exercise
For the curve \\(y^2 = x^3 + 5x + 7\\), what is \\((-1,1) + (-1,1)\\)?
---
>>> a, b = 5, 7
>>> x1, y1 = -1, -1
>>> # formula in python
>>> # s = (3*x1**2+a)/(2*y1)
>>> s = (3*x1**2+a)/(2*y1)  #/
>>> # x3 = s**2 - 2*x1
>>> x3 = s**2 - 2*x1  #/
>>> # y3 = s*(x1-x3) - y1
>>> y3 = s*(x1-x3) - y1  #/
>>> # print the coordinates
>>> print(x3, y3)  #/
18.0 77.0

#endexercise
#unittest
ecc:PointTest:test_add2:
#endunittest
'''


from random import randint
from unittest import TestCase

from ecc import FieldElement, Point


def __add__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot add two numbers in different Fields')
    num = (self.num + other.num) % self.prime
    prime = self.prime
    return self.__class__(num, prime)


def __sub__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot add two numbers in different Fields')
    num = (self.num - other.num) % self.prime
    prime = self.prime
    return self.__class__(num, prime)


def __mul__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot add two numbers in different Fields')
    num = (self.num * other.num) % self.prime
    prime = self.prime
    return self.__class__(num, prime)


def __pow__(self, n):
    prime = self.prime
    num = pow(self.num, n % (prime - 1), prime)
    return self.__class__(num, prime)


def __truediv__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot add two numbers in different Fields')
    num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
    prime = self.prime
    return self.__class__(num, prime)


def __init__(self, x, y, a, b):
    self.a = a
    self.b = b
    self.x = x
    self.y = y
    if self.x is None and self.y is None:
        return
    if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(self.x, self.y))


def point_add(self, other):
    if self.a != other.a or self.b != other.b:
        raise TypeError('Points {}, {} are not on the same curve'.format(self, other))
    if self.x is None:
        return other
    if other.x is None:
        return self
    if self.x == other.x and self.y != other.y:
        return self.__class__(None, None, self.a, self.b)
    if self.x != other.x:
        s = (other.y - self.y) / (other.x - self.x)
        x = s**2 - self.x - other.x
        y = s * (self.x - x) - self.y
        return self.__class__(x, y, self.a, self.b)
    else:
        s = (3 * self.x**2 + self.a) / (2 * self.y)
        x = s**2 - 2 * self.x
        y = s * (self.x - x) - self.y
        return self.__class__(x, y, self.a, self.b)


class SessionTest(TestCase):

    def test_apply(self):
        FieldElement.__add__ = __add__
        FieldElement.__sub__ = __sub__
        FieldElement.__mul__ = __mul__
        FieldElement.__pow__ = __pow__
        FieldElement.__truediv__ = __truediv__
        Point.__init__ = __init__
        Point.__add__ = point_add
