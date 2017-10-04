### Problems

Find nodes here: https://bitnodes.21.co/nodes/

1. Connect to a node and parse some messages

Example program
-----
import socket
from binascii import unhexlify, hexlify

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
msg = unhexlify('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
s.connect(('<find a node above>', 8333))
s.sendall(msg)
data = s.recv(200)
print(hexlify(data))