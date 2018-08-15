from io import BytesIO
from random import randint

import asyncio
import time

from block import Block
from network import NetworkEnvelope, TESTNET_NETWORK_MAGIC
from helper import (
    double_sha256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

class NodeConnection:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.magic = TESTNET_NETWORK_MAGIC
        self.q = asyncio.Queue()
    
    async def connect(self, loop):
        self.reader, self.writer = await asyncio.open_connection(
            host=self.host, port=self.port)
        print('connected')
        # construct version message
        version = int_to_little_endian(70015, 4)
        services = int_to_little_endian(0, 8)
        timestamp = int_to_little_endian(int(time.time()), 8)
        ip = b'\x00' * 18 + b'\xff\xff' + b'\x00' * 6
        nonce = int_to_little_endian(randint(0, 2**64), 8)
        user_agent = b'nobody'
        ua = bytes([len(user_agent)]) + user_agent
        latest_block = int_to_little_endian(0, 4)
        # set relay to false so we don't get inv messages just yet
        relay = b'\x00' 
        payload = version + services + timestamp + ip + ip + nonce + ua + latest_block + relay
        self.send(b'version', payload)
        print('sent version')
        await asyncio.wait([self.receive(), self.process_queue()])

    def send(self, command, payload):
        network_message = NetworkEnvelope(command, payload, self.magic)
        print('sending {}'.format(network_message))
        self.writer.write(network_message.serialize())

    async def receive(self):
        print("start receiving")
        while True:
            magic = await self.reader.read(4)
            if magic != self.magic:
                raise RuntimeError('Network Magic not at beginning of stream {}'.format(magic.hex()))
            command = await self.reader.read(12)
            payload_length = little_endian_to_int(await self.reader.read(4))
            checksum = await self.reader.read(4)
            payload = await self.reader.readexactly(payload_length)
            # check the checksum
            if double_sha256(payload)[:4] != checksum:
                raise RuntimeError('Payload and Checksum do not match: {} vs {}'.format(checksum.hex(), double_sha256(payload)[:4].hex()))
            await self.q.put(NetworkEnvelope(command, payload))

    async def process_queue(self):
        print("start processing")
        while True:
            envelope = await self.q.get()
            if envelope.command.startswith(b'version'):
                print('sending verack')
                self.send(b'verack', b'')
            elif envelope.command.startswith(b'verack'):
                print('received verack')
                version = int_to_little_endian(70015, 4)
                hash_count = encode_varint(1)
                # testnet genesis block
                self.last_block = bytes.fromhex('000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943')[::-1]
                end_block = b'\x00' * 32
                payload = version + hash_count + self.last_block + end_block

                self.send(b'getheaders', payload)
            elif envelope.command.startswith(b'headers'):
                print('received headers')
                stream = BytesIO(envelope.payload)
                num_headers = read_varint(stream)
                blocks = []
                b = b''
                first = True
                with open('blocks.db', 'ab') as f:
                    for _ in range(num_headers):
                        b = stream.read(80)
                        if first:
                            if b[4:36] != self.last_block:
                                raise RuntimeError('not continuous')
                            else:
                                first = False
                        num_txs = little_endian_to_int(stream.read(1))
                        if num_txs != 0:
                            raise RuntimeError('got more than 0 txs')
                        f.write(b)
                self.last_block = double_sha256(b)
                print(stream.read(10).hex())
                version = int_to_little_endian(70015, 4)
                hash_count = encode_varint(1)
                end_block = b'\x00' * 32
                payload = version + hash_count + self.last_block + end_block
                self.send(b'getheaders', payload)
gpg2            else:
                print(envelope)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    node_list = [
        'tbtc.programmingblockchain.com',
	'13.58.133.145',
	'139.59.69.9',
	'186.19.136.144',
	'209.250.238.91',
	'138.201.129.98',
	'88.208.34.114',
	'101.132.41.225',
	'167.99.140.183',
	'5.189.166.193',
	'52.53.231.136',
	'13.64.255.185',
	'52.59.254.220',
	'144.76.27.145',
	'213.186.121.88',
	'45.32.154.183',
	'81.169.237.132',
	'136.24.85.165',
	'13.71.129.234',
	'159.89.147.223',
	'13.210.32.80',
	'159.203.84.97',
	'88.99.162.199',
    ]
    node = NodeConnection(host=node_list[0], port=18333)
    task = loop.run_until_complete(node.connect(loop))
    loop.close()

