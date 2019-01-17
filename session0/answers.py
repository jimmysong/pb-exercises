'''
#code
>>> import helper

#endcode
#markdown
### This is a Jupyter Notebook
You can write Python code and it will execute. You can write the typical 'hello world' program like this:

```python
print('hello world')
```

You can execute by pressing shift-enter. Try it! You can also click the Run button in the toolbar.
#endmarkdown
#code
>>> print('hello world')
hello world

#endcode
#code
>>> s = 'hello world'
>>> b = b'hello world'
>>> 
>>> print(s==b) # False
False
>>> 
>>> # You convert from string to bytes this way:
>>> 
>>> hello_world_bytes = s.encode('ascii')
>>> print(hello_world_bytes == b) # True
True
>>> 
>>> # You convert from bytes to string this way:
>>> 
>>> hello_world_string = b.decode('ascii')
>>> print(hello_world_string == s) # True
True

#endcode
#exercise
You can do a lot more than just print "hello world"

This is a fully functioning Python3 interpreter so you can write functions and objects like in the next box.

Try printing the 21st Fibonacci number below instead of the 11th. You can add caching if you want to practice coding in Python.
---
>>> def fib(n):
...     if n in (0,1):
...         return 1
...     else:
...         return fib(n-1) + fib(n-2)
>>> print(fib(20))  #/print(fib(10))  # CHANGE THIS LINE
10946

#endexercise
#markdown
### A few things you should remember in Python 3

Strings and bytes are now different

```python
s = 'hello world'
b = b'hello world'
```

These may look the same but the 'b' prefix means that the variable `b` is bytes whereas the variable `s` is a string. Basically, the on-disk characters on the system are bytes and the actual symbols in unicode are strings. A good explanation of the difference is [here](http://www.diveintopython3.net/strings.html).
#endmarkdown
#code
>>> s = 'hello world'
>>> b = b'hello world'
>>> 
>>> print(s==b) # False
False
>>> 
>>> # You convert from string to bytes this way:
>>> 
>>> hello_world_bytes = s.encode('ascii')
>>> print(hello_world_bytes == b) # True
True
>>> 
>>> # You convert from bytes to string this way:
>>> 
>>> hello_world_string = b.decode('ascii')
>>> print(hello_world_string == s) # True
True

#endcode
#markdown
### Imports

You already have unit tests that are written for you.
Your task is to make them pass.
We can import various modules to make our experience using Jupyter more pleasant.
This way, making everything work will be a lot easier.
#endmarkdown
#code
>>> # this is how you import an entire module
>>> import helper
>>> 
>>> # this is how you import a particular function, class or constant
>>> from helper import little_endian_to_int
>>> 
>>> # used in the next exercise
>>> some_long_variable_name = 'something'

#endcode
#exercise
#### Jupyter Tips

The two most useful commands are tab and shift-tab

Tab lets you tab-complete. Try pressing tab after the `some` below. This will complete to the variable name that's there from the last cell.

Shift-Tab gives you a function/method signature. Try pressing shift-tab after the `little_endian_to_int` below. That's also there from the last cell.
---
>>> some_long_variable_name  #/some  # press *tab* here
'something'
>>> little_endian_to_int(b'\\x00')  #/little_endian_to_int()  # press shift-tab here
0

#endexercise
#unittest
helper:HelperTest:test_bytes:
Open [helper.py](/edit/session0/helper.py) and implement the `bytes_to_str` and `str_to_bytes` functions. Once you're done editing, run the cell below.
#endunittest
#markdown
### Getting Help

If you can't get this, there's a [complete directory](/tree/session0/complete) that has the [helper.py file](/edit/session0/complete/helper.py) and the [session0.ipynb file](/notebooks/session0/complete/session0.ipynb) which you can use to get the answers.
#endmarkdown
#markdown
### Useful Python 3 Idioms

You can reverse a list by using `[::-1]`:

```python
a = [1, 2, 3, 4, 5]
print(a[::-1]) # [5, 4, 3, 2, 1]
```

Also works on both strings and bytes:

```python
s = 'hello world'
print(s[::-1]) # 'dlrow olleh'
b = b'hello world'
print(b[::-1]) # b'dlrow olleh'
```

Indexing bytes will get you the numerical value:

```python
print(b'&'[0]) # 38 since & is charcter #38 
```

You can do the reverse by using bytes:

```python
print(bytes([38])) # b'&'
```
#endmarkdown
#code
>>> a = [1, 2, 3, 4, 5]
>>> print(a[::-1]) # [5, 4, 3, 2, 1]
[5, 4, 3, 2, 1]
>>> 
>>> s = 'hello world'
>>> print(s[::-1]) # 'dlrow olleh'
dlrow olleh
>>> b = b'hello world'
>>> print(b[::-1]) # b'dlrow olleh'
b'dlrow olleh'
>>> 
>>> print(b'&'[0]) # 38 since & charcter #38
38
>>> 
>>> print(bytes([38])) # b'&'
b'&'

#endcode
#markdown
### Python Tricks

Here is how we convert binary to/from hex:
#endmarkdown
#code
>>> print(b'hello world'.hex())
68656c6c6f20776f726c64
>>> print(bytes.fromhex('68656c6c6f20776f726c64'))
b'hello world'

#endcode
#exercise
Reverse this hex dump: `b010a49c82b4bc84cc1dfd6e09b2b8114d016041efaf591eca88959e327dd29a`

Hint: you'll want to turn this into binary data, reverse and turn it into hex again
---
>>> h = 'b010a49c82b4bc84cc1dfd6e09b2b8114d016041efaf591eca88959e327dd29a'
>>> # convert to binary (bytes.fromhex)
>>> b = bytes.fromhex(h)  #/
>>> # reverse ([::-1])
>>> b_rev = b[::-1]  #/
>>> # convert to hex()
>>> h_rev = b_rev.hex()  #/
>>> # print the result
>>> print(h_rev)  #/
9ad27d329e9588ca1e59afef4160014d11b8b2096efd1dcc84bcb4829ca410b0

#endexercise
#markdown
### Modular Arithmetic

If you don't remember Modular Arithmetic, it's this function on python

```python
39 % 12
```

The result is 3 because that is the remainder after division (39 / 12 == 3 + 3/12).

Some people like to call it "wrap-around" math. If it helps, think of modular arithmetic like a clock:

![clock](http://latex.artofproblemsolving.com/f/4/d/f4daa2601de14fddf3d8441e16cc322a25e85354.png)

Think of taking the modulo as asking the question "what hour will it be 39 hours from now?"

If you're still confused, please take a look at [this](https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/what-is-modular-arithmetic) article.
#endmarkdown
#code
>>> print(39 % 12)
3

#endcode
#exercise

Find the modulo 19 of these numbers:

* 99
* \\(456 \cdot 444\\)
* \\(9^{77}\\)

(note python uses ** to do exponentiation)
---
>>> prime = 19
>>> print(99 % prime)  #/
4
>>> print(456*444 % prime)  #/
0
>>> print(9**77 % prime)  #/
16

#endexercise
#markdown
### Converting from bytes to int and back

Converting from bytes to integer requires learning about Big and Little Endian encoding. Essentially any number greater than 255 can be encoded in two ways, with the "Big End" going first or the "Little End" going first.

Normal human reading is from the "Big End". For example 123 is read as 100 + 20 + 3. Some computer systems encode integers with the "Little End" first.

A number like 500 is encoded this way in Big Endian:

0x01f4 (256 + 244)

But this way in Little Endian:

0xf401 (244 + 256)

In Python we can convert an integer to big or little endian using a built-in method:

```python
n = 1234567890
big_endian = n.to_bytes(4, 'big')  # b'\x49\x96\x02\xd2'
little_endian = n.to_bytes(4, 'little')  # b'\xd2\x02\x96\x49'
```

We can also convert from bytes to an integer this way:

```python
big_endian = b'\x49\x96\x02\xd2'
n = int.from_bytes(big_endian, 'big')  # 1234567890
little_endian = b'\xd2\x02\x96\x49'
n = int.from_bytes(little_endian, 'little')  # 1234567890
```

#endmarkdown
#code
>>> n = 1234567890
>>> big_endian = n.to_bytes(4, 'big')
>>> little_endian = n.to_bytes(4, 'little')
>>> 
>>> print(big_endian.hex())
499602d2
>>> print(little_endian.hex())
d2029649
>>> 
>>> print(int.from_bytes(big_endian, 'big'))
1234567890
>>> print(int.from_bytes(little_endian, 'little'))
1234567890

#endcode
#exercise
Convert the following:

 * 8675309 to 8 bytes in big endian
 * interpret ```b'\x11\x22\x33\x44\x55'``` as a little endian integer
---
>>> n = 8675309
>>> print(n.to_bytes(8, 'big'))  #/
b'\\x00\\x00\\x00\\x00\\x00\\x84_\\xed'
>>> little_endian = b'\x11\x22\x33\x44\x55'
>>> print(int.from_bytes(little_endian, 'little'))  #/
366216421905

#endexercise
#unittest
helper:HelperTest:test_little_endian_to_int:
We'll want to convert from little-endian bytes to an integer often, so write a function that will do this.
#endunittest
#unittest
helper:HelperTest:test_int_to_little_endian:
Similarly, we'll want to do the inverse operation, so write a function that will convert an integer to little-endian bytes given the number and the number of bytes it should take up.
#endunittest
'''


from unittest import TestCase

import helper


def bytes_to_str(b, encoding='ascii'):
    return b.decode(encoding)

def str_to_bytes(s, encoding='ascii'):
    return s.encode(encoding)

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


class SessionTest(TestCase):

    def test_apply(self):
        helper.bytes_to_str = bytes_to_str
        helper.str_to_bytes = str_to_bytes
        helper.little_endian_to_int = little_endian_to_int
        helper.int_to_little_endian = int_to_little_endian
