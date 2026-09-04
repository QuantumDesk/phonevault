"""Dependency-free EVM verification primitives for the host side of the AOA client.

The host must not trust the phone's `transactionHash` or `address` fields: it recomputes the
hash from the signed bytes and recovers the signer from the signature, then compares. Everything
here is pure Python (Keccak-256, RLP, secp256k1 public-key recovery) so the host tool keeps its
single pinned dependency (pyusb). Performance is irrelevant at one transaction per approval.
"""

# --------------------------------------------------------------------------- Keccak-256

_MASK64 = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# rotation offsets r[x][y]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_RATE = 136  # bytes, for a 256-bit digest


def _rol(value, shift):
    shift %= 64
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state):
    a = state
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= _RC[rnd]
    return a


def keccak256(data):
    """Keccak-256 as used by Ethereum (original padding 0x01…0x80, NOT SHA3-256)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), _RATE):
        block = padded[offset:offset + _RATE]
        for i in range(_RATE // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = _keccak_f(state)
    out = bytearray()
    for i in range(4):  # 32 bytes = 4 lanes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


# --------------------------------------------------------------------------- RLP encoding

def _length_prefix(length, offset):
    if length < 56:
        return bytes([offset + length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(length_bytes)]) + length_bytes


def rlp_encode(item):
    """Minimal RLP encoder: ints (minimal big-endian, 0 → empty), bytes, and lists thereof."""
    if isinstance(item, bool):
        raise TypeError("bool is not RLP-encodable")
    if isinstance(item, int):
        if item < 0:
            raise ValueError("negative integers are not RLP-encodable")
        payload = b"" if item == 0 else item.to_bytes((item.bit_length() + 7) // 8, "big")
        return rlp_encode(payload)
    if isinstance(item, (bytes, bytearray)):
        item = bytes(item)
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _length_prefix(len(item), 0x80) + item
    if isinstance(item, (list, tuple)):
        body = b"".join(rlp_encode(element) for element in item)
        return _length_prefix(len(body), 0xC0) + body
    raise TypeError(f"cannot RLP-encode {type(item).__name__}")


# --------------------------------------------------------------------------- secp256k1

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
CURVE_ORDER = _N


def _inv(value, modulus):
    return pow(value, modulus - 2, modulus)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        slope = (3 * x1 * x1) * _inv(2 * y1, _P) % _P
    else:
        slope = (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _on_curve(point):
    if point is None:
        return False
    x, y = point
    return (y * y - (x * x * x + 7)) % _P == 0


def recover_public_key(message_hash, r, s, y_parity):
    """Recover the (x, y) public key that produced signature (r, s, y_parity) over message_hash."""
    if not isinstance(message_hash, (bytes, bytearray)) or len(message_hash) != 32:
        raise ValueError("message hash must be 32 bytes")
    if y_parity not in (0, 1):
        raise ValueError("y_parity must be 0 or 1")
    if not (0 < r < _N and 0 < s < _N):
        raise ValueError("signature components out of range")
    if r >= _P:
        raise ValueError("unsupported signature (r >= p)")
    # Lift x = r to a curve point with the requested parity.
    alpha = (r * r * r + 7) % _P
    beta = pow(alpha, (_P + 1) // 4, _P)
    if (beta * beta) % _P != alpha:
        raise ValueError("signature r is not a valid x-coordinate")
    y = beta if (beta & 1) == y_parity else _P - beta
    big_r = (r, y)
    if _point_mul(_N, big_r) is not None:
        raise ValueError("signature point has wrong order")
    e = int.from_bytes(message_hash, "big") % _N
    r_inv = _inv(r, _N)
    # Q = r^-1 (s·R − e·G)
    s_r = _point_mul(s, big_r)
    e_g = _point_mul(e, _G)
    minus_e_g = None if e_g is None else (e_g[0], (-e_g[1]) % _P)
    q = _point_mul(r_inv, _point_add(s_r, minus_e_g))
    if q is None or not _on_curve(q):
        raise ValueError("recovered key is not on the curve")
    return q


def public_key_to_address(public_key):
    x, y = public_key
    return "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex()


def recover_address(message_hash, r, s, y_parity):
    return public_key_to_address(recover_public_key(message_hash, r, s, y_parity))


# --------------------------------------------------------------------------- EIP-1559

def eip1559_signing_hash(fields):
    """keccak256(0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to,
    value, data, accessList])) — the message the phone actually signed. `to` and `data` are
    raw bytes; the access list is always empty in this protocol."""
    payload = [
        fields["chainId"], fields["nonce"], fields["maxPriorityFeePerGas"],
        fields["maxFeePerGas"], fields["gasLimit"], fields["to"], fields["value"],
        fields["data"], [],
    ]
    return keccak256(b"\x02" + rlp_encode(payload))


def eip1559_transaction_hash(raw_signed_transaction):
    """keccak256 of the full typed-transaction bytes (0x02 ‖ rlp(signed fields))."""
    if not raw_signed_transaction or raw_signed_transaction[0] != 0x02:
        raise ValueError("not an EIP-1559 typed transaction")
    return keccak256(raw_signed_transaction)


# --------------------------------------------------------------------------- test-only signing

def sign_for_test(message_hash, private_key, k):
    """Deterministic ECDSA (fixed k) used ONLY by tests to build vectors; never for real keys."""
    e = int.from_bytes(message_hash, "big") % _N
    big_r = _point_mul(k, _G)
    r = big_r[0] % _N
    s = _inv(k, _N) * (e + r * private_key) % _N
    y_parity = big_r[1] & 1
    if s > _N // 2:
        s = _N - s
        y_parity ^= 1
    return r, s, y_parity


def private_key_to_address(private_key):
    return public_key_to_address(_point_mul(private_key, _G))
