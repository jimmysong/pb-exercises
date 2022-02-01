from io import BytesIO
from unittest import TestCase

from helper import (
    encode_varint,
    encode_varstr,
    filter_null,
    hash256,
    int_to_little_endian,
    read_varint,
    read_varstr,
)
from script import Script
from siphash import SipHash_2_4


BASIC_FILTER_TYPE = 0
GOLOMB_P = 19
GOLOMB_M = int(round(1.497137 * 2**GOLOMB_P))


def _siphash(key, value):
    if len(key) != 16:
        raise ValueError("Key should be 16 bytes")
    sip = SipHash_2_4(key)
    sip.update(value)
    return sip.hash()


def hash_to_range(key, value, f):
    """Returns a number between 0 and f-1, uniformly distributed.
    Uses siphash-2-4."""
    return _siphash(key, value) * f >> 64


def hashed_items(key, items):
    n = len(items)
    f = n * GOLOMB_M
    result = []
    for item in items:
        result.append(hash_to_range(key, item, f))
    return sorted(result)


def encode_golomb(x, p):
    """converts a number x to a golomb-encoded array of 0's and 1's"""
    # quotient when dividing x by 2^p
    q = x >> p
    # q 1's and a 0 at the end
    result = [1] * q + [0]
    # the last p bits of x
    result += [x & (1 << (p - i - 1)) > 0 for i in range(p)]
    return result


def decode_golomb(bits, p):
    """converts a golomb-encoded array of 0's and 1's to a number"""
    q = 0
    while bits[0] != 0:
        q += 1
        bits.pop(0)
    bits.pop(0)
    r = 0
    for _ in range(p):
        r <<= 1
        if bits.pop(0) == 1:
            r |= 1
    return (q << p) + r


def pack_bits(bits):
    """converts bits to a byte-string"""
    num_bytes = len(bits)
    bits += [0] * (-num_bytes % 8)
    result = 0
    for bit in bits:
        result <<= 1
        if bit:
            result |= 1
    return result.to_bytes(len(bits) // 8, "big")


def unpack_bits(byte_string):
    bits = []
    for byte in byte_string:
        for _ in range(8):
            if byte & 0x80:
                bits.append(1)
            else:
                bits.append(0)
            byte <<= 1
    return bits


def serialize_gcs(sorted_items):
    last_value = 0
    result = []
    for item in sorted_items:
        delta = item - last_value
        result += encode_golomb(delta, GOLOMB_P)
        last_value = item
    return encode_varint(len(sorted_items)) + pack_bits(result)


def encode_gcs(key, items):
    """Returns the golomb-coded-set byte-string which is the sorted
    hashes of the items"""
    sorted_items = hashed_items(key, items)
    return serialize_gcs(sorted_items)


def decode_gcs(key, gcs):
    """Returns the sorted hashes of the items from the golomb-coded-set"""
    s = BytesIO(gcs)
    num_items = read_varint(s)
    bits = unpack_bits(s.read())
    items = []
    current = 0
    for _ in range(num_items):
        delta = decode_golomb(bits, GOLOMB_P)
        current += delta
        items.append(current)
    return items


class CompactFilter:
    def __init__(self, key, hashes):
        self.key = key
        self.hashes = set(hashes)
        self.f = len(self.hashes) * GOLOMB_M

    def __repr__(self):
        result = f"{self.key.hex()}:\n\n"
        for h in sorted(list(self.hashes)):
            result += f"{h.hex()}\n"
        return result

    def __eq__(self, other):
        return self.key == other.key and sorted(list(self.hashes)) == sorted(
            list(other.hashes)
        )

    @classmethod
    def parse(cls, key, filter_bytes):
        return cls(key, set(decode_gcs(key, filter_bytes)))

    def hash(self):
        return hash256(self.serialize())

    def serialize(self):
        return serialize_gcs(sorted(list(self.hashes)))

    def compute_hash(self, raw_script_pubkey):
        return hash_to_range(self.key, raw_script_pubkey, self.f)

    def __contains__(self, script_pubkey):
        raw_script_pubkey = script_pubkey.raw_serialize()
        return self.compute_hash(raw_script_pubkey) in self.hashes


class GetCFiltersMessage:
    command = b"getcfilters"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=1, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFilterMessage:
    command = b"cfilter"
    define_network = False

    def __init__(self, filter_type, block_hash, filter_bytes):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_bytes = filter_bytes
        self.cf = CompactFilter.parse(block_hash[::-1][:16], filter_bytes)

    def __eq__(self, other):
        return (
            self.filter_type == other.filter_type
            and self.block_hash == other.block_hash
            and self.filter_bytes == other.filter_bytes
        )

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        block_hash = s.read(32)[::-1]
        filter_bytes = read_varstr(s)
        return cls(filter_type, block_hash, filter_bytes)

    def hash(self):
        return hash256(self.filter_bytes)

    def __contains__(self, script_pubkey):
        return script_pubkey in self.cf


class GetCFHeadersMessage:
    command = b"getcfheaders"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=0, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFHeadersMessage:
    command = b"cfheaders"
    define_network = False

    def __init__(self, filter_type, stop_hash, previous_filter_header, filter_hashes):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.previous_filter_header = previous_filter_header
        self.filter_hashes = filter_hashes
        current = self.previous_filter_header
        for filter_hash in self.filter_hashes:
            current = hash256(filter_hash + current)
        self.last_header = current

    def __repr__(self):
        result = f"up to {self.stop_hash.hex()}\nstarting from {self.previous_filter_header.hex()}\n\n"
        for fh in self.filter_hashes:
            result += f"{fh.hex()}\n"
        return result

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        previous_filter_header = s.read(32)
        filter_hashes_length = read_varint(s)
        filter_hashes = []
        for _ in range(filter_hashes_length):
            filter_hashes.append(s.read(32))
        return cls(filter_type, stop_hash, previous_filter_header, filter_hashes)


class GetCFCheckPointMessage:

    command = b"getcfcheckpt"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, stop_hash=None):
        self.filter_type = filter_type
        if stop_hash is None:
            raise RuntimeError("Need a stop hash")
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += self.stop_hash[::-1]
        return result


class CFCheckPointMessage:
    command = b"cfcheckpt"
    define_network = False

    def __init__(self, filter_type, stop_hash, filter_headers):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.filter_headers = filter_headers

    def __repr__(self):
        result = f"up to {self.stop_hash.hex()}\n\n"
        for fh in self.filter_headers:
            result += f"{fh.hex()}\n"
        return result

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        filter_headers_length = read_varint(s)
        filter_headers = []
        for _ in range(filter_headers_length):
            filter_headers.append(s.read(32))
        return cls(filter_type, stop_hash, filter_headers)


class CompactFilterTest(TestCase):
    def test_siphash(self):
        zero_key = b"\x00" * 16
        result = _siphash(zero_key, b"Hello world")
        want = 0xC9E8A3021F3822D9
        self.assertEqual(result, want)
        result = _siphash(zero_key, b"")
        want = 0x1E924B9D737700D7
        self.assertEqual(result, want)
        result = _siphash(zero_key, b"12345678123")
        want = 0xF95D77CCDB0649F
        self.assertEqual(result, want)
        test_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        result = _siphash(test_key, b"")
        want = 0x726FDB47DD0E0E31
        self.assertEqual(result, want)
        result = _siphash(test_key, b"\x00")
        want = 0x74F839C593DC67FD
        self.assertEqual(result, want)
        with self.assertRaises(ValueError):
            _siphash(b"\x00" * 4, b"\x00")

    def test_golomb(self):
        tests = (
            # x, p, want
            (0, 2, b"\x00"),
            (1, 2, b"\x20"),
            (2, 2, b"\x40"),
            (3, 2, b"\x60"),
            (4, 2, b"\x80"),
            (5, 2, b"\x90"),
            (6, 2, b"\xa0"),
            (7, 2, b"\xb0"),
            (8, 2, b"\xc0"),
            (9, 2, b"\xc8"),
            (0, 8, b"\x00\x00"),
            (1, 8, b"\x00\x80"),
            (2, 8, b"\x01\x00"),
            (128, 8, b"\x40\x00"),
            (256, 8, b"\x80\x00"),
            (257, 8, b"\x80\x40"),
        )
        for x, p, want in tests:
            result = pack_bits(encode_golomb(x, p))
            self.assertEqual(result, want)
            self.assertEqual(decode_golomb(unpack_bits(result), p), x)

    def test_hashed_items(self):
        from block import Block

        tests = [
            # ["Block Height,Block Hash,Block,[Prev Output Scripts for Block],Previous Basic Header,Basic Filter,Basic Header,Notes"],
            [
                0,
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
                [],
                "0000000000000000000000000000000000000000000000000000000000000000",
                "019dfca8",
                "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750",
                "Genesis block",
            ],
            [
                2,
                "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820",
                "0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d235340101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0432e7494d010e062f503253482fffffffff0100f2052a010000002321038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac00000000",
                [],
                "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1",
                "0174a170",
                "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0",
                "",
            ],
            [
                3,
                "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10",
                "0100000020782a005255b657696ea057d5b98f34defcf75196f64f6eeac8026c0000000041ba5afc532aae03151b8aa87b65e1594f97504a768e010c98c0add79216247186e7494dffff001d058dc2b60101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0486e7494d0151062f503253482fffffffff0100f2052a01000000232103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac00000000",
                [],
                "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0",
                "016cf7a0",
                "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a",
                "",
            ],
            [
                49291,
                "0000000018b07dca1b28b4b5a119f6d6e71698ce1ed96f143f54179ce177a19c",
                "02000000abfaf47274223ca2fea22797e44498240e482cb4c2f2baea088962f800000000604b5b52c32305b15d7542071d8b04e750a547500005d4010727694b6e72a776e55d0d51ffff001d211806480201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d038bc0000102062f503253482fffffffff01a078072a01000000232102971dd6034ed0cf52450b608d196c07d6345184fcb14deb277a6b82d526a6163dac0000000001000000081cefd96060ecb1c4fbe675ad8a4f8bdc61d634c52b3a1c4116dee23749fe80ff000000009300493046022100866859c21f306538152e83f115bcfbf59ab4bb34887a88c03483a5dff9895f96022100a6dfd83caa609bf0516debc2bf65c3df91813a4842650a1858b3f61cfa8af249014730440220296d4b818bb037d0f83f9f7111665f49532dfdcbec1e6b784526e9ac4046eaa602204acf3a5cb2695e8404d80bf49ab04828bcbe6fc31d25a2844ced7a8d24afbdff01ffffffff1cefd96060ecb1c4fbe675ad8a4f8bdc61d634c52b3a1c4116dee23749fe80ff020000009400483045022100e87899175991aa008176cb553c6f2badbb5b741f328c9845fcab89f8b18cae2302200acce689896dc82933015e7230e5230d5cff8a1ffe82d334d60162ac2c5b0c9601493046022100994ad29d1e7b03e41731a4316e5f4992f0d9b6e2efc40a1ccd2c949b461175c502210099b69fdc2db00fbba214f16e286f6a49e2d8a0d5ffc6409d87796add475478d601ffffffff1e4a6d2d280ea06680d6cf8788ac90344a9c67cca9b06005bbd6d3f6945c8272010000009500493046022100a27400ba52fd842ce07398a1de102f710a10c5599545e6c95798934352c2e4df022100f6383b0b14c9f64b6718139f55b6b9494374755b86bae7d63f5d3e583b57255a01493046022100fdf543292f34e1eeb1703b264965339ec4a450ec47585009c606b3edbc5b617b022100a5fbb1c8de8aaaa582988cdb23622838e38de90bebcaab3928d949aa502a65d401ffffffff1e4a6d2d280ea06680d6cf8788ac90344a9c67cca9b06005bbd6d3f6945c8272020000009400493046022100ac626ac3051f875145b4fe4cfe089ea895aac73f65ab837b1ac30f5d875874fa022100bc03e79fa4b7eb707fb735b95ff6613ca33adeaf3a0607cdcead4cfd3b51729801483045022100b720b04a5c5e2f61b7df0fcf334ab6fea167b7aaede5695d3f7c6973496adbf1022043328c4cc1cdc3e5db7bb895ccc37133e960b2fd3ece98350f774596badb387201ffffffff23a8733e349c97d6cd90f520fdd084ba15ce0a395aad03cd51370602bb9e5db3010000004a00483045022100e8556b72c5e9c0da7371913a45861a61c5df434dfd962de7b23848e1a28c86ca02205d41ceda00136267281be0974be132ac4cda1459fe2090ce455619d8b91045e901ffffffff6856d609b881e875a5ee141c235e2a82f6b039f2b9babe82333677a5570285a6000000006a473044022040a1c631554b8b210fbdf2a73f191b2851afb51d5171fb53502a3a040a38d2c0022040d11cf6e7b41fe1b66c3d08f6ada1aee07a047cb77f242b8ecc63812c832c9a012102bcfad931b502761e452962a5976c79158a0f6d307ad31b739611dac6a297c256ffffffff6856d609b881e875a5ee141c235e2a82f6b039f2b9babe82333677a5570285a601000000930048304502205b109df098f7e932fbf71a45869c3f80323974a826ee2770789eae178a21bfc8022100c0e75615e53ee4b6e32b9bb5faa36ac539e9c05fa2ae6b6de5d09c08455c8b9601483045022009fb7d27375c47bea23b24818634df6a54ecf72d52e0c1268fb2a2c84f1885de022100e0ed4f15d62e7f537da0d0f1863498f9c7c0c0a4e00e4679588c8d1a9eb20bb801ffffffffa563c3722b7b39481836d5edfc1461f97335d5d1e9a23ade13680d0e2c1c371f030000006c493046022100ecc38ae2b1565643dc3c0dad5e961a5f0ea09cab28d024f92fa05c922924157e022100ebc166edf6fbe4004c72bfe8cf40130263f98ddff728c8e67b113dbd621906a601210211a4ed241174708c07206601b44a4c1c29e5ad8b1f731c50ca7e1d4b2a06dc1fffffffff02d0223a00000000001976a91445db0b779c0b9fa207f12a8218c94fc77aff504588ac80f0fa02000000000000000000",
                [
                    "5221033423007d8f263819a2e42becaaf5b06f34cb09919e06304349d950668209eaed21021d69e2b68c3960903b702af7829fadcd80bd89b158150c85c4a75b2c8cb9c39452ae",
                    "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821021d69e2b68c3960903b702af7829fadcd80bd89b158150c85c4a75b2c8cb9c39452ae",
                    "522102a7ae1e0971fc1689bd66d2a7296da3a1662fd21a53c9e38979e0f090a375c12d21022adb62335f41eb4e27056ac37d462cda5ad783fa8e0e526ed79c752475db285d52ae",
                    "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821022adb62335f41eb4e27056ac37d462cda5ad783fa8e0e526ed79c752475db285d52ae",
                    "512103b9d1d0e2b4355ec3cdef7c11a5c0beff9e8b8d8372ab4b4e0aaf30e80173001951ae",
                    "76a9149144761ebaccd5b4bbdc2a35453585b5637b2f8588ac",
                    "522103f1848b40621c5d48471d9784c8174ca060555891ace6d2b03c58eece946b1a9121020ee5d32b54d429c152fdc7b1db84f2074b0564d35400d89d11870f9273ec140c52ae",
                    "76a914f4fa1cc7de742d135ea82c17adf0bb9cf5f4fb8388ac",
                ],
                "ed47705334f4643892ca46396eb3f4196a5e30880589e4009ef38eae895d4a13",
                "0afbc2920af1b027f31f87b592276eb4c32094bb4d3697021b4c6380",
                "b6d98692cec5145f67585f3434ec3c2b3030182e1cb3ec58b855c5c164dfaaa3",
                "Tx pays to empty output script",
            ],
            [
                180480,
                "00000000fd3ceb2404ff07a785c7fdcc76619edc8ed61bd25134eaa22084366a",
                "020000006058aa080a655aa991a444bd7d1f2defd9a3bbe68aabb69030cf3b4e00000000d2e826bfd7ef0beaa891a7eedbc92cd6a544a6cb61c7bdaa436762eb2123ef9790f5f552ffff001d0002c90f0501000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0300c102024608062f503253482fffffffff01c0c6072a01000000232102e769e60137a4df6b0df8ebd387cca44c4c57ae74cc0114a8e8317c8f3bfd85e9ac00000000010000000381a0802911a01ffb025c4dea0bc77963e8c1bb46313b71164c53f72f37fe5248010000000151ffffffffc904b267833d215e2128bd9575242232ac2bc311550c7fc1f0ef6f264b40d14c010000000151ffffffffdf0915666649dba81886519c531649b7b02180b4af67d6885e871299e9d5f775000000000151ffffffff0180817dcb00000000232103bb52138972c48a132fc1f637858c5189607dd0f7fe40c4f20f6ad65f2d389ba4ac0000000001000000018da38b434fba82d66052af74fc5e4e94301b114d9bc03f819dc876398404c8b4010000006c493046022100fe738b7580dc5fb5168e51fc61b5aed211125eb71068031009a22d9bbad752c5022100be5086baa384d40bcab0fa586e4f728397388d86e18b66cc417dc4f7fa4f9878012103f233299455134caa2687bdf15cb0becdfb03bd0ff2ff38e65ec6b7834295c34fffffffff022ebc1400000000001976a9147779b7fba1c1e06b717069b80ca170e8b04458a488ac9879c40f000000001976a9142a0307cd925dbb66b534c4db33003dd18c57015788ac0000000001000000026139a62e3422a602de36c873a225c1d3ca5aeee598539ceecb9f0dc8d1ad0f83010000006b483045022100ad9f32b4a0a2ddc19b5a74eba78123e57616f1b3cfd72ce68c03ea35a3dda1f002200dbd22aa6da17213df5e70dfc3b2611d40f70c98ed9626aa5e2cde9d97461f0a012103ddb295d2f1e8319187738fb4b230fdd9aa29d0e01647f69f6d770b9ab24eea90ffffffff983c82c87cf020040d671956525014d5c2b28c6d948c85e1a522362c0059eeae010000006b4830450221009ca544274c786d30a5d5d25e17759201ea16d3aedddf0b9e9721246f7ef6b32e02202cfa5564b6e87dfd9fd98957820e4d4e6238baeb0f65fe305d91506bb13f5f4f012103c99113deac0d5d044e3ac0346abc02501542af8c8d3759f1382c72ff84e704f7ffffffff02c0c62d00000000001976a914ae19d27efe12f5a886dc79af37ad6805db6f922d88ac70ce2000000000001976a9143b8d051d37a07ea1042067e93efe63dbf73920b988ac000000000100000002be566e8cd9933f0c75c4a82c027f7d0c544d5c101d0607ef6ae5d07b98e7f1dc000000006b483045022036a8cdfd5ea7ebc06c2bfb6e4f942bbf9a1caeded41680d11a3a9f5d8284abad022100cacb92a5be3f39e8bc14db1710910ef7b395fa1e18f45d41c28d914fcdde33be012102bf59abf110b5131fae0a3ce1ec379329b4c896a6ae5d443edb68529cc2bc7816ffffffff96cf67645b76ceb23fe922874847456a15feee1655082ff32d25a6bf2c0dfc90000000006a47304402203471ca2001784a5ac0abab583581f2613523da47ec5f53df833c117b5abd81500220618a2847723d57324f2984678db556dbca1a72230fc7e39df04c2239942ba942012102925c9794fd7bb9f8b29e207d5fc491b1150135a21f505041858889fa4edf436fffffffff026c840f00000000001976a914797fb8777d7991d8284d88bfd421ce520f0f843188ac00ca9a3b000000001976a9146d10f3f592699265d10b106eda37c3ce793f7a8588ac00000000",
                [
                    "",
                    "",
                    "",
                    "76a9142903b138c24be9e070b3e73ec495d77a204615e788ac",
                    "76a91433a1941fd9a37b9821d376f5a51bd4b52fa50e2888ac",
                    "76a914e4374e8155d0865742ca12b8d4d14d41b57d682f88ac",
                    "76a914001fa7459a6cfc64bdc178ba7e7a21603bb2568f88ac",
                    "76a914f6039952bc2b307aeec5371bfb96b66078ec17f688ac",
                ],
                "b109139671dbedc2b6fcd499a5480a7461ae458af8ff9411d819aa64ba6995d1",
                "0db414c859a07e8205876354a210a75042d0463404913d61a8e068e58a3ae2aa080026",
                "a0af77e0a7ed20ea78d2def3200cc24f08217dcd51755c7c7feb0e2ba8316c2d",
                "Tx spends from empty output script",
            ],
        ]
        for (
            block_height,
            block_hash_hex,
            full_block_hex,
            scripts,
            prev_hash_hex,
            cfilter_hex,
            filter_header_hex,
            notes,
        ) in tests:
            key = bytes.fromhex(block_hash_hex)[::-1][:16]
            b = Block.parse(BytesIO(bytes.fromhex(full_block_hex)))
            tx_out_scripts = b.get_tx_out_scripts()
            items = filter_null(
                [bytes.fromhex(s) for s in scripts]
                + [s.raw_serialize() for s in tx_out_scripts]
            )
            raw_cf = encode_gcs(key, items)
            self.assertEqual(raw_cf.hex(), cfilter_hex, notes)
            decoded_items = decode_gcs(key, raw_cf)
            self.assertEqual(decoded_items, hashed_items(key, items))
            cf = CompactFilter(key, decoded_items)
            cf2 = CompactFilter.parse(key, raw_cf)
            self.assertEqual(cf, cf2)
            self.assertEqual(cf.serialize(), raw_cf)
            for raw_hex in scripts:
                if raw_hex == "":
                    continue
                raw_script_pubkey = encode_varstr(bytes.fromhex(raw_hex))
                script_pubkey = Script.parse(BytesIO(raw_script_pubkey))
                self.assertTrue(script_pubkey in cf)
            for script_pubkey in tx_out_scripts:
                self.assertTrue(script_pubkey in cf)
            prev_hash = bytes.fromhex(prev_hash_hex)[::-1]
            filter_header = hash256(hash256(raw_cf) + prev_hash)[::-1]
            self.assertEqual(filter_header_hex, filter_header.hex(), notes)
