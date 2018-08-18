import socket
import time

from io import BytesIO
from random import randint

from helper import (
    double_sha256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class NetworkEnvelope:

    def __init__(self, command, payload, testnet=False):
        if len(command) < 12:
            command += b'\x00' * (12 - len(command))
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        magic = s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
        # command 12 bytes
        command = s.read(12)
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of double-sha256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = double_sha256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic
        result = self.magic
        # command 12 bytes
        result += self.command
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of double-sha256 of payload
        result += double_sha256(self.payload)[:4]
        # payload
        result += self.payload
        return result


class SocketController:
    
    def __init__(self, host, port=None, testnet=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.testnet= testnet
        self.stream = self.socket.makefile('rb', None)

    def send(self, command, payload):
        envelope = NetworkEnvelope(command, payload, testnet=self.testnet)
        self.socket.sendall(envelope.serialize())

    def wait_for_commands(self, commands):
        envelope = self.read()
        last_command = envelope.command
        if last_command.startswith(b'version'):
            # send verack
            self.send(b'verack', b'')
        elif last_command.startswith(b'ping'):
            # send pong
            self.send(b'pong', envelope.payload)
        if last_command in commands:
            return envelope
        else:
            return self.wait_for_commands(commands)
        

    def read(self):
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        print(envelope)
        return envelope
