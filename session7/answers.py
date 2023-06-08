"""
#code
>>> import block, helper, network

#endcode
#exercise
Parse this message
```
f9beb4d976657261636b000000000000000000005df6e0e2
```
---
>>> from helper import little_endian_to_int
>>> msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
>>> # first 4 are network magic
>>> magic = msg[:4]  #/
>>> # next 12 are command
>>> command = msg[4:16]  #/
>>> # next 4 are payload length
>>> payload_length = little_endian_to_int(msg[16:20])  #/
>>> # next 4 are checksum
>>> checksum = msg[20:24]  #/
>>> # rest is payload
>>> payload = msg[24:]  #/
>>> # print the command
>>> print(command)  #/
b'verack\\x00\\x00\\x00\\x00\\x00\\x00'

#endexercise
#unittest
network:NetworkEnvelopeTest:test_parse:
#endunittest
#unittest
network:NetworkEnvelopeTest:test_serialize:
#endunittest
#unittest
network:GetHeadersMessageTest:test_serialize:
#endunittest
#unittest
network:HeadersMessageTest:test_parse:
#endunittest
#code
>>> # Handshake Example
>>> from network import SimpleNode, VersionMessage, VerAckMessage
>>> node = SimpleNode('signet.programmingbitcoin.com', network="signet")
>>> version = VersionMessage()
>>> node.send(version)
>>> print(node.wait_for(VerAckMessage).command)
b'verack'

#endcode
#unittest
network:SimpleNodeTest:test_handshake:
#endunittest
#code
>>> # Block Header Download Example
>>> from block import GENESIS_BLOCKS
>>> from helper import target_to_bits
>>> from network import GetHeadersMessage, HeadersMessage, SimpleNode
>>> net = "mainnet"
>>> node = SimpleNode('mainnet.programmingbitcoin.com', network=net)
>>> node.handshake()
>>> last_block = GENESIS_BLOCKS[net]
>>> epoch_start_block = GENESIS_BLOCKS[net]
>>> current_height = 1
>>> for _ in range(20):
...     getheaders = GetHeadersMessage(start_block=last_block.hash())
...     node.send(getheaders)
...     headers = node.wait_for(HeadersMessage)
...     for header in headers:
...         if not header.check_pow():
...             raise RuntimeError(f'bad proof of work at block {count}')
...         if last_block != GENESIS_BLOCKS[net]:
...             if header.prev_block != last_block.hash():
...                 raise RuntimeError(f'discontinuous block at {count}')
...             if current_height % 2016 == 0:
...                 expected_bits = last_block.new_bits(epoch_start_block)
...                 if header.bits != expected_bits:
...                     raise RuntimeError(f'bits are off {header.bits.hex()} vs {expected_bits.hex()}')
...                 epoch_start_block = header
...                 print(header.id())
...         last_block = header
...         current_height += 1
00000000a141216a896c54f211301c436e557a8d55900637bbdce14c6c7bddef
00000000ca4b69045a03d7b20624def97a5366418648d5005e82fd3b345d20d0
000000004c63907577f6beb84a97af137738c2342de8ee7872c0cd4df1dcb213
000000001c1eae2f038485775bad4d77500698b069259f98900d9f6ab646b92c
0000000012ee5cd7ab160c09b83754c095fef94ccead459dbc45184a56154053
0000000083f8b6d4f1d818b7e8771e1505cb9fd2259702257ea409afa5ff63e0
00000000a29242d3931efe2c21b6318f24cbf79df7d97eb7bd8076593fe0d2c4
00000000112c2a0b4d83fdd2b153b82235d50e088bdd86ce36fb3d1928ff2552
00000000b91ca39c169b3fabc9f7b99058a6a1edf09ecd6d7c52d62ee99b01fe
000000000f1aef56190aee63d33a373e6487132d522ff4cd98ccfc96566d461e
000000001897323d6feb2358a313ab11b2b6e033fe5b1e86e8f30ad0a1701de0
0000000049195c8e3e5d13bb807cf2170cdf30abef7263cb245b21b49cf46df2
00000000b9c449d7272fa6ca3f8d028e1ac02381129bfcdc0a1f4e67c6d007cc
000000008a89868a8f27c33e46b78752ed92763b9d45ae8791e0f9cb5acdd97c
000000000fa8bfa0f0dd32f956b874b2c7f1772c5fbedcb1b35e03335c7fb0a8
000000004f2886a170adb7204cb0c7a824217dd24d11a74423d564c4e0904967
000000002732d387256b57cabdcb17767e3d30e220ea73f844b1907c0b5919ea
0000000040514b192e6ca247d83388bf11cb1d5e980610ae2c6324cbb0594b32
0000000015bb50096055846954f7120e30d6aa2bd5ab8d4a4055ceacc853328a

#endcode
#exercise
Download the first 40,000 blocks for testnet and validate them.
---
>>> from network import SimpleNode, GetHeadersMessage, HeadersMessage
>>> from block import GENESIS_BLOCKS
>>> # connect to testnet.programmingbitcoin.com with network
>>> net = "testnet"
>>> node = SimpleNode('testnet.programmingbitcoin.com', network=net)  #/
>>> # handshake
>>> node.handshake()  #/
>>> # set the last block hash to the GENESIS_BLOCKS[net]
>>> last_block = GENESIS_BLOCKS[net]  #/
>>> # set the first block of the epoch to the genesis block
>>> epoch_start_block = GENESIS_BLOCKS[net]  #/
>>> # set the current height to 1
>>> current_height = 1  #/
>>> # loop until we we get 40,000 blocks
>>> while current_height < 40000:  #/
...     # create a GetHeadersMessage starting from the last block we have
...     getheaders = GetHeadersMessage(start_block=last_block.hash())  #/
...     # send the getheaders message
...     node.send(getheaders)  #/
...     # wait for the HeadersMessage in response
...     headers = node.wait_for(HeadersMessage)  #/
...     # loop through the headers from the headers message
...     for header in headers:  #/
...         # check the proof of work
...         if not header.check_pow():  #/
...             raise RuntimeError(f'bad proof of work at block {count}')  #/
...         # only check if the current hash isn't the first one
...         if last_block != GENESIS_BLOCKS[net]:  #/
...             # the prev_block of the current block should be the last block
...             if header.prev_block != last_block.hash():  #/
...                 raise RuntimeError(f'discontinuous block at {count}')  #/
...             # when it's a multiple of 2016
...             if current_height % 2016 == 0:  #/
...                 # set the expected bits using the new_bits method using the last block
...                 expected_bits = last_block.new_bits(epoch_start_block)  #/
...                 # check that the bits are what we expect
...                 if header.bits != expected_bits:  #/
...                     raise RuntimeError(f'bits are off {header.bits.hex()} vs {expected_bits.hex()}')  #/
...                 # set the epoch start block to the current one
...                 epoch_start_block = header  #/
...                 # print the current id  #/
...                 print(header.id())  #/
...         # increment the current_height
...         current_height += 1  #/
...         # set the last_block to the current header's hash
...         last_block = header  #/
0000000089d757fd95d79f7fcc2bc25ca7fc16492dca9aa610730ea05d9d3de9
000000001af3b22a7598b10574deb6b3e2d596f36d62b0a49cb89a1f99ab81eb
000000000be66197ad285aedd52e56036f28d595fe281858bc5d562173d4d6de
00000000118da1e2165a19307b86f87eba814845e8a0f99734dce279ca3fb029
000000007c4fc01a14af8067762fb807144b1b59cd4ec79ffc61efae3439757d
0000000000e5d282a44a897650367ebccc890f8550263e64487a34612975bd7c
000000000e92deb9fc5350ecce48cd26561d3707f6acc5474889ce34a2faf0a7
00000000161a4a693fd5d5964bb48a732e230273e88489e0e85fae1294e63699
000000000becf05ed9a5093f553f03a85f24a831fa9f1ffcca9a5a5066fef020
000000001cf5440e7c9ae69f655759b17a32aad141896defd55bb895b7cfc44e
0000000060662a5ca0b2aa015afe39299fa4e281c4c71a58cb816f5732cfabc1
00000000005da26890c97ecfca4d51974b42338f1b0b4b299c9a3158d8b06e4e
0000000003665532235284c300585ffd9e0d44a16a66ed06351c1d06801322b2
0000000011b9447373685d9ee78e17d2e0be2701e589aa787c7702dd9299e807
0000000002d3cd050eb30bd369bcd5a7098f5c4a88f93c031e3bf06d8b58b9e1
0000000000162a3da1229fc058b904bde0e28ab1fad489f8805df2561b854727
0000000000a206c0ee4c1e42badc056f97692ee3909ffd5416e3362b2c1ea465
00000000015a8d54db1b04dbb13eaed7b8c0b7a82c107a1e8a388b296a84529d
00000000015bb4069249fa1f41ae61d8a7447aaacc33c50dacd3c3654377fa43

#endexercise
#code
>>> # Merkle Parent Example
>>> from helper import hash256
>>> tx_hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
>>> tx_hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
>>> parent = hash256(tx_hash0+tx_hash1)
>>> print(parent.hex())
8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd

#endcode
#exercise
Calculate the Merkle parent of these hashes:
```
f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0
3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181
```
---
>>> from helper import hash256
>>> hex_hash1 = 'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0'
>>> hex_hash2 = '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181'
>>> # bytes.fromhex to get the bin hashes
>>> hash1 = bytes.fromhex(hex_hash1)  #/
>>> hash2 = bytes.fromhex(hex_hash2)  #/
>>> # hash256 the combination
>>> parent = hash256(hash1+hash2)  #/
>>> # hex() to see the result
>>> print(parent.hex())  #/
7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800

#endexercise
#unittest
helper:HelperTest:test_merkle_parent:
#endunittest
#code
>>> # Merkle Parent Level Example
>>> from helper import merkle_parent
>>> hex_hashes = [
...     'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
...     'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
...     'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
...     '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
...     '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
... ]
>>> hashes = [bytes.fromhex(x) for x in hex_hashes]
>>> if len(hashes) % 2 == 1:
...     hashes.append(hashes[-1])
>>> parent_level = []
>>> for i in range(0, len(hex_hashes), 2):
...     parent = merkle_parent(hashes[i], hashes[i+1])
...     print(parent.hex())
...     parent_level.append(parent)
8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd
7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800
3ecf6115380c77e8aae56660f5634982ee897351ba906a6837d15ebc3a225df0

#endcode
#exercise
Calculate the next Merkle Parent Level given these hashes
```
8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd
7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800
ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7
68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069
43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27
```
---
>>> from helper import merkle_parent
>>> hex_hashes = [
...     '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
...     '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
...     'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
...     '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
...     '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
... ]
>>> # bytes.fromhex to get all the hashes in binary
>>> hashes = [bytes.fromhex(h) for h in hex_hashes]  #/
>>> # if the number of hashes is odd, duplicate the last one
>>> if len(hashes) % 2 == 1:  #/
...     hashes.append(hashes[-1])  #/
>>> # initialize parent level
>>> parent_level = []  #/
>>> # skip by two: use range(0, len(hashes), 2)
>>> for i in range(0, len(hashes), 2):  #/
...     # calculate merkle_parent of i and i+1 hashes
...     parent = merkle_parent(hashes[i], hashes[i+1])  #/
...     # print the hash's hex
...     print(parent.hex())  #/
...     # add parent to parent level
...     parent_level.append(parent)  #/
26906cb2caeb03626102f7606ea332784281d5d20e2b4839fbb3dbb37262dbc1
717a0d17538ff5ad2c020bab38bdcde66e63f3daef88f89095f344918d5d4f96
d6c56a5281021a587f5a1e0dd4674bff012c69d960136d96e6d72261d5b696ae

#endexercise
#unittest
helper:HelperTest:test_merkle_parent_level:
#endunittest
#code
>>> # Merkle Root Example
>>> from helper import merkle_parent_level
>>> hex_hashes = [
...     'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
...     'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
...     'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
...     '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
...     '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
...     '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
...     '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
...     'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
...     'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
...     '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
...     '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
...     'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
... ]
>>> current_level = [bytes.fromhex(x) for x in hex_hashes]
>>> while len(current_level) > 1:
...     current_level = merkle_parent_level(current_level)
>>> print(current_level[0].hex())
acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6

#endcode
#exercise
Calculate the Merkle Root given these hashes
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```
---
>>> from helper import merkle_parent_level
>>> hex_hashes = [
...     '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
...     '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
...     '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
...     'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
...     '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
...     '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
...     'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
...     '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
...     '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
...     '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
...     '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
... ]
>>> # bytes.fromhex to get all the hashes in binary
>>> hashes = [bytes.fromhex(h) for h in hex_hashes]  #/
>>> # initialize current level to be the hashes
>>> current_level = hashes  #/
>>> # loop until current_level has only 1 element
>>> while len(current_level) > 1:  #/
...     # make the current level the parent level
...     current_level = merkle_parent_level(current_level)  #/
>>> # print the root's hex
>>> print(current_level[0].hex())  #/
a67772634e542799333c6c98bc903e36b652918a8d8a9e069391c55b4276c8a1

#endexercise
#unittest
helper:HelperTest:test_merkle_root:
#endunittest
#code
>>> # Block Merkle Root Example
>>> from helper import merkle_root
>>> tx_hex_hashes = [
...     '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
...     '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
...     '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
...     'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
...     '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
...     '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
...     'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
... ]
>>> current_level = [bytes.fromhex(x)[::-1] for x in tx_hex_hashes]
>>> print(merkle_root(current_level)[::-1].hex())
654d6181e18e4ac4368383fdc5eead11bf138f9b7ac1e15334e4411b3c4797d9

#endcode
#exercise
Validate the merkle root for this block from Testnet:
Block Hash:
```
0000000000000451fa80fcdb243b84c35eaae215a85a8faa880559e8239e6f20
```

Transaction Hashes:
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```
---
>>> from helper import merkle_root
>>> want = '4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301'
>>> tx_hex_hashes = [
...     '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
...     '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
...     '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
...     'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
...     '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
...     '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
...     'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
...     '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
...     '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
...     '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
...     '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
... ]
>>> # bytes.fromhex and reverse ([::-1]) to get all the hashes in binary
>>> hashes = [bytes.fromhex(h)[::-1] for h in tx_hex_hashes]  #/
>>> # get the merkle root
>>> root = merkle_root(hashes)  #/
>>> # see if the reversed root is the same as the wanted root
>>> print(root[::-1].hex() == want)  #/
True

#endexercise
#unittest
block:BlockTest:test_validate_merkle_root:
#endunittest
#unittest
network:GetDataMessageTest:test_serialize:
#endunittest
#exercise
Validate the merkle root for this block from Testnet via network protocol:
Block Hash:
```
0000000000044b01a9440b34f582fe171c7b8642fedd0ebfccf8fdf6a1810900
```
---
>>> from network import SimpleNode, GetDataMessage, BLOCK_DATA_TYPE
>>> from block import Block
>>> block_hex = '0000000000044b01a9440b34f582fe171c7b8642fedd0ebfccf8fdf6a1810900'
>>> block_hash = bytes.fromhex(block_hex)
>>> # connect to testnet.programmingbitcoin.com on testnet
>>> node = SimpleNode('testnet.programmingbitcoin.com', network="testnet")  #/
>>> # handshake
>>> node.handshake()  #/
>>> # create a GetDataMessage
>>> getdata = GetDataMessage()  #/
>>> # request a block with (BLOCK_DATA_TYPE, block_hash)
>>> getdata.add_data(BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the getdata message
>>> node.send(getdata)  #/
>>> # wait for the block message in response (class is Block)
>>> block_obj = node.wait_for(Block)  #/
>>> # check the proof of work
>>> if not block_obj.check_pow():  #/
...     raise RuntimeError('bad proof of work')  #/
>>> # validate the tx_hashes
>>> if not block_obj.validate_merkle_root():  #/
...     raise RuntimeError('bad merkle root')  #/
>>> # print the merkle root hex
>>> print(block_obj.merkle_root.hex())  #/
627bf8053bd767ad72c6afcd2d91638311f9c7520905a634be13aa8853f7a446

#endexercise
"""


from unittest import TestCase

import helper
import merkleblock

from block import Block, TWO_WEEKS, MAX_TARGET
from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    target_to_bits,
)
from merkleblock import MerkleTree
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    NetworkEnvelope,
    SimpleNode,
    VerAckMessage,
    VersionMessage,
    BLOCK_DATA_TYPE,
    MAGIC,
)
from tx import Tx


@classmethod
def parse_ne(cls, s, network="mainnet"):
    magic = s.read(4)
    if magic != MAGIC[network]:
        raise RuntimeError(f"magic is not right {magic.hex()} vs {MAGIC[network].hex()}")
    command = s.read(12)
    command = command.strip(b"\x00")
    payload_length = little_endian_to_int(s.read(4))
    checksum = s.read(4)
    payload = s.read(payload_length)
    calculated_checksum = hash256(payload)[:4]
    if calculated_checksum != checksum:
        raise RuntimeError("checksum does not match")
    return cls(command, payload, network=network)


def serialize_ne(self):
    result = self.magic
    result += self.command + b"\x00" * (12 - len(self.command))
    result += int_to_little_endian(len(self.payload), 4)
    result += hash256(self.payload)[:4]
    result += self.payload
    return result


def serialize_vm(self):
    result = int_to_little_endian(self.version, 4)
    result += int_to_little_endian(self.services, 8)
    result += int_to_little_endian(self.timestamp, 8)
    result += int_to_little_endian(self.receiver_services, 8)
    result += b"\x00" * 10 + b"\xff\xff" + self.receiver_ip
    result += int_to_little_endian(self.receiver_port, 2)
    result += int_to_little_endian(self.sender_services, 8)
    result += b"\x00" * 10 + b"\xff\xff" + self.sender_ip
    result += int_to_little_endian(self.sender_port, 2)
    result += self.nonce
    result += encode_varint(len(self.user_agent))
    result += self.user_agent
    result += int_to_little_endian(self.latest_block, 4)
    if self.relay:
        result += b"\x01"
    else:
        result += b"\x00"
    return result


def serialize_gh(self):
    result = int_to_little_endian(self.version, 4)
    result += encode_varint(self.num_hashes)
    result += self.start_block[::-1]
    result += self.end_block[::-1]
    return result


def serialize_gd(self):
    result = encode_varint(len(self.data))
    for data_type, identifier in self.data:
        result += int_to_little_endian(data_type, 4)
        result += identifier[::-1]
    return result


@classmethod
def parse_h(cls, stream):
    num_headers = read_varint(stream)
    headers = []
    for _ in range(num_headers):
        header = Block.parse(stream)
        headers.append(header)
        if len(header.tx_hashes) != 0:
            raise RuntimeError("number of txs not 0")
    return cls(headers)


def handshake(self):
    version = VersionMessage()
    self.send(version)
    self.wait_for(VerAckMessage)


def merkle_parent(hash1, hash2):
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    if len(hashes) == 1:
        raise RuntimeError("Cannot take a parent level with only 1 item")
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hashes):
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def validate_merkle_root(self):
    hashes = [h[::-1] for h in self.tx_hashes]
    root = merkle_root(hashes)
    return root[::-1] == self.merkle_root


def new_bits(self, beginning_block):
    time_differential = self.timestamp - beginning_block.timestamp
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = self.target() * time_differential // TWO_WEEKS
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    return target_to_bits(new_target)


class SessionTest(TestCase):
    def test_apply(self):
        NetworkEnvelope.parse = parse_ne
        NetworkEnvelope.serialize = serialize_ne
        VersionMessage.serialize = serialize_vm
        GetHeadersMessage.serialize = serialize_gh
        GetDataMessage.serialize = serialize_gd
        HeadersMessage.parse = parse_h
        SimpleNode.handshake = handshake
        helper.merkle_parent = merkle_parent
        merkleblock.merkle_parent = merkle_parent
        helper.merkle_parent_level = merkle_parent_level
        helper.merkle_root = merkle_root
        Block.validate_merkle_root = validate_merkle_root
        Block.new_bits = new_bits
