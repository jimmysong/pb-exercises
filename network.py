import asyncio
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
    async def parse(cls, s, testnet=False):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        magic = await s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
        # command 12 bytes
        command = await s.read(12)
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(await s.read(4))
        # checksum 4 bytes, first four of double-sha256 of payload
        checksum = await s.read(4)
        # payload is of length payload_length
        payload = await s.read(payload_length)
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


class TxSender:

    def __init__(self, raw_tx, host, port, testnet=False, timeout=10):
        self.raw_tx = raw_tx
        self.tx_hash = double_sha256(raw_tx)
        self.inv_payload = b'\x01' + int_to_little_endian(1, 4) + self.tx_hash
        self._sent = False
        self._accepted = False
        self.host = host
        self.port = port
        self.magic = magic
        self.reader = None
        self.writer = None
        self.q = asyncio.Queue()
        self.keep_looping = True
        self.timeout = timeout

    async def connect(self, loop):
        self.reader, self.writer = await asyncio.open_connection(
            host=self.host, port=self.port)
        print('connected to {}:{}'.format(self.host, self.port))

        # construct version message
        version = int_to_little_endian(70015, 4)
        services = int_to_little_endian(0, 8)
        timestamp = int_to_little_endian(int(time.time()), 8)
        ip = b'\x00' * 18 + b'\xff\xff' + b'\x00' * 6
        nonce = int_to_little_endian(randint(0, 2**64), 8)
        user_agent = b'nobody'
        ua = bytes([len(user_agent)]) + user_agent
        latest_block = int_to_little_endian(0, 4)

        payload = version + services + timestamp + ip + ip + nonce + ua + latest_block
        self.send(b'version', payload)
        await asyncio.wait([self.receive(), self.process_queue()])

    def send(self, command, payload):
        network_message = NetworkEnvelope(command, payload, self.magic)
        print('sending {}'.format(network_message))
        self.writer.write(network_message.serialize())

    async def receive(self):
        print("start receiving")
        while self.keep_looping:
            network_envelope = await NetworkEnvelope.parse(self.reader, self.magic)
            print(network_envelope)
            await self.q.put(network_envelope)

    async def process_queue(self):
        print("start processing")
        start = time.time()
        while self.keep_looping:
            envelope = await self.q.get()
            command = envelope.command.strip(b'\x00').decode('ascii')
            if command == 'version':
                self.send(b'verack', b'')
            elif command == 'sendheaders':
                self.send(b'headers', encode_varint(0))
            elif command == 'ping':
                self.send(b'pong', envelope.payload)
                if not self._sent:
                    # tell them we have a tx
                    self.send(b'inv', self.inv_payload)
                elif not self._accepted:
                    self.send(b'tx', self.raw_tx)
                self.send(b'mempool', b'')
            elif command == 'getdata':
                if envelope.payload == self.inv_payload:
                    self.send(b'tx', self.raw_tx)
                    self._sent = True
                elif self._sent:
                    print('TX rejected')
                    self.keep_looping = False
            elif command == 'feefilter':
                minimum = little_endian_to_int(envelope.payload)
                print('TX requires fee: {} minimum'.format(minimum))
            elif command == 'inv':
                stream = BytesIO(envelope.payload)
                num_inv = read_varint(stream)
                for _ in range(num_inv):
                    inv_type = little_endian_to_int(stream.read(4))
                    inv_hash = stream.read(32)
                    if inv_type == 1 and inv_hash == self.tx_hash:
                        print('TX successfully sent')
                        self.keep_looping = False
                self.send(b'inv', self.inv_payload)
            else:
                print(envelope)
            if time.time()-start < self.timeout:
                self.keep_looping = False
