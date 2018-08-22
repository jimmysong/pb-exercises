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
        # strip the trailing 0's
        command = command.strip(b'\x00')
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
        # fill with 0's
        result += self.command + b'\x00' * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of double-sha256 of payload
        result += double_sha256(self.payload)[:4]
        # payload
        result += self.payload
        return result


class VersionMessage:

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333,
                 nonce=None, user_agent=b'/programmingblockchain:0.1/',
                 latest_block=0, relay=True):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # IPV4 is 18 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 18 + b'\xff\xff' + self.receiver_ip
        # receiver port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.receiver_port, 2)
        # IPV4 is 18 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 18 + b'\xff\xff' + self.sender_ip
        # sender port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.sender_port, 2)
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result


class GetHeadersMessage:

    def __init__(self, version=70015, num_hashes=1, starting_block=None, ending_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if starting_block is None:
            raise RuntimeError('a starting block is required')
        self.starting_block = starting_block
        if ending_block is None:
            self.ending_block = b'\x00' * 32
        else:
            self.ending_block = ending_block

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.starting_block[::-1]
        result += self.ending_block[::-1]
        return result

    
class SimpleNode:
    
    def __init__(self, host, port=None, testnet=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet= testnet
        # connect to socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        # create a stream that we can use with the rest of the library
        self.stream = self.socket.makefile('rb', None)

    def handshake(self):
        # send a version message
        payload = VersionMessage().serialize()
        self.send(b'version', payload)
        # wait for a verack message
        self.wait_for_commands({b'verack'})
        
    def send(self, command, payload):
        # create a network envelope
        envelope = NetworkEnvelope(command, payload, testnet=self.testnet)
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def wait_for_commands(self, commands):
        # get the newest envelope
        envelope = self.read()
        # get the command to be evaluated
        command = envelope.command
        # we know how to respond to version and ping, handle that here
        if command.startswith(b'version'):
            # send verack
            self.send(b'verack', b'')
        elif command.startswith(b'ping'):
            # send pong
            self.send(b'pong', envelope.payload)
        # if we got one of the commands we're waiting for, return it
        # otherwise, parse the next command with wait_for_command
        if command in commands:
            return envelope
        else:
            return self.wait_for_commands(commands)
        
    def read(self):
        return NetworkEnvelope.parse(self.stream, testnet=self.testnet)
