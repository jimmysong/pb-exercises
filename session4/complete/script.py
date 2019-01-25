from io import BytesIO
from unittest import TestCase

from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


class Script:

    def __init__(self, commands=None):
        if commands is None:
            self.commands = []
        else:
            self.commands = commands

    def __repr__(self):
        result = ''
        for command in self.commands:
            if type(command) == int:
                if OP_CODE_NAMES.get(command):
                    name = OP_CODE_NAMES.get(command)
                else:
                    name = 'OP_[{}]'.format(command)
                result += '{} '.format(name)
            else:
                result += '{} '.format(command.hex())
        return result

    def __add__(self, other):
        return Script(self.commands + other.commands)

    @classmethod
    def parse(cls, s):
        # get the length of the entire field
        length = read_varint(s)
        # initialize the commands array
        commands = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have a command set n to be the current byte
                n = current_byte
                # add the next n bytes as a command
                commands.append(s.read(n))
                # increase the count by n
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                commands.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                commands.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an op code. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of commands
                commands.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(commands)

    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        # go through each command
        for command in self.commands:
            # if the command is an integer, it's an op code
            if type(command) == int:
                # turn the command into a single byte integer using int_to_little_endian
                result += int_to_little_endian(command, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(command)
                # for large lengths, we have to use a pushdata op code
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long a command')
                result += command
        return result

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def evaluate(self, z):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        commands = self.commands[:]
        stack = []
        altstack = []
        while len(commands) > 0:
            command = commands.pop(0)
            if type(command) == int:
                # do what the op code says
                operation = OP_CODE_FUNCTIONS[command]
                if command in (99, 100):
                    # op_if/op_notif require the commands array
                    if not operation(stack, commands):
                        print('bad op: {}'.format(OP_CODE_NAMES[command]))
                        return False
                elif command in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        print('bad op: {}'.format(OP_CODE_NAMES[command]))
                        return False
                elif command in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        print('bad op: {}'.format(OP_CODE_NAMES[command]))
                        return False
                else:
                    if not operation(stack):
                        print('bad op: {}'.format(OP_CODE_NAMES[command]))
                        return False
            else:
                # add the command to the stack
                stack.append(command)
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True


class ScriptTest(TestCase):

    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
        script = Script.parse(script_pubkey)
        want = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(script.commands[0].hex(), want.hex())
        want = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(script.commands[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)
