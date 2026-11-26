"""Independent reference for the fixed test vectors in testdata/vectors.json (Python standard
library only).

Implements Ed25519 (RFC 8032), X25519 (RFC 7748), ChaCha20-Poly1305 and XChaCha20-Poly1305
(RFC 8439, draft-irtf-cfrg-xchacha-03), HKDF (RFC 5869) and HPKE base mode with
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 (RFC 9180) from their specifications,
checks each against a published test vector, then recomputes every Hangar Drive format from
its description (field framing, HMAC object IDs, Padme, directory nodes, file manifests, device
log entries of every kind, epochs, records of every kind, first, re-anchor, side and merge
commits, recovery and pairing codes, the signed pairing offer, safety numbers, NFC keys, the
three case keys, the format characters and the display name rule of the name policy) and
compares the result with testdata/vectors.json. The Rust tests (src/vectors.rs) compare the
crate's own output with the same file, so both implementations must agree. It needs Python 3.14
(Unicode 16.0 in unicodedata, the version of the name policy's tables).

The primitives section is taken from the sister project's hangar-team-crypto test_vectors.py
(MIT, same owner) unchanged; everything from "Hangar Drive formats" on is written for Drive.

Slow on purpose (textbook big-integer arithmetic); the inputs are fixed, nothing here is secret.

Run:   py -3 crates/hangar-drive-crypto/test_vectors.py
Write: py -3 crates/hangar-drive-crypto/test_vectors.py --write   (only after a format change)
"""

import base64
import hashlib
import hmac
import json
import pathlib
import struct
import sys
import unicodedata

VECTORS = pathlib.Path(__file__).parent / "testdata" / "vectors.json"
UNICODE_VERSION = "16.0.0"

# ---------------------------------------------------------------------------------------------
# Ed25519, RFC 8032 section 6 (reference implementation, rewritten)
# ---------------------------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * pow(5, P - 2, P) % P
G = (_recover_x(G_Y, 0), G_Y, 1, _recover_x(G_Y, 0) * G_Y % P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, Gg, H = B - A, Dd - C, Dd + C, B + A
    return (E * F, Gg * H, F * Gg, E * H)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _compress(point):
    zinv = pow(point[2], P - 2, P)
    x = point[0] * zinv % P
    y = point[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _sha512_int(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed):
    a, _ = _expand_seed(seed)
    return _compress(_mul(a, G))


def ed25519_sign(seed, message):
    a, prefix = _expand_seed(seed)
    public = _compress(_mul(a, G))
    r = _sha512_int(prefix + message) % L
    big_r = _compress(_mul(r, G))
    h = _sha512_int(big_r + public + message) % L
    s = (r + h * a) % L
    return big_r + int.to_bytes(s, 32, "little")


# ---------------------------------------------------------------------------------------------
# X25519, RFC 7748 section 5
# ---------------------------------------------------------------------------------------------


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(k, u):
    k = int.from_bytes(_clamp(k), "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return int.to_bytes(x2 * pow(z2, P - 2, P) % P, 32, "little")


def x25519_public(k):
    return x25519(k, int.to_bytes(9, 32, "little"))


# ---------------------------------------------------------------------------------------------
# ChaCha20, Poly1305, AEADs (RFC 8439, draft-irtf-cfrg-xchacha-03)
# ---------------------------------------------------------------------------------------------


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def _rounds(state):
    s = list(state)
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return s


def chacha20_block(key, counter, nonce):
    state = CONSTANTS + list(struct.unpack("<8I", key)) + [counter] + list(
        struct.unpack("<3I", nonce)
    )
    s = _rounds(state)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(s, state)])


def chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def hchacha20(key, nonce16):
    state = CONSTANTS + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    s = _rounds(state)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i : i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return int.to_bytes((acc + s) & ((1 << 128) - 1), 16, "little")


def _pad16(data):
    return b"\x00" * (-len(data) % 16)


def chacha20poly1305_seal(key, nonce, plaintext, aad):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, plaintext)
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac)


def xchacha20poly1305_seal(key, nonce24, plaintext, aad):
    subkey = hchacha20(key, nonce24[:16])
    return chacha20poly1305_seal(subkey, b"\x00" * 4 + nonce24[16:], plaintext, aad)


# ---------------------------------------------------------------------------------------------
# HKDF (RFC 5869) and HPKE base mode (RFC 9180)
# ---------------------------------------------------------------------------------------------


def hkdf_extract(salt, ikm):
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def hkdf(ikm, info, length):
    return hkdf_expand(hkdf_extract(b"", ikm), info, length)


KEM_SUITE = b"KEM" + struct.pack(">H", 0x0020)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x0020, 0x0001, 0x0003)


def _labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def hpke_derive_keypair(ikm):
    prk = _labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = _labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    return sk, x25519_public(sk)


def hpke_seal_base(pk_r, info, aad, plaintext, ikm_e):
    sk_e, pk_e = hpke_derive_keypair(ikm_e)
    dh = x25519(sk_e, pk_r)
    eae_prk = _labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    shared = _labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", pk_e + pk_r, 32)
    psk_id_hash = _labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(HPKE_SUITE, shared, b"secret", b"")
    key = _labeled_expand(HPKE_SUITE, secret, b"key", context, 32)
    nonce = _labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    return pk_e, chacha20poly1305_seal(key, nonce, plaintext, aad)


# ---------------------------------------------------------------------------------------------
# Anchors: each primitive against its published vector
# ---------------------------------------------------------------------------------------------


def h(text):
    return bytes.fromhex(text)


def check_anchors():
    seed = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert ed25519_public(seed) == h(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ), "RFC 8032 test 1 public key"
    assert ed25519_sign(seed, b"") == h(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ), "RFC 8032 test 1 signature"
    assert x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), "RFC 7748 5.2"
    pk_r = h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
    assert x25519_public(
        h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
    ) == pk_r, "RFC 9180 A.2.1 pkRm"
    enc, ct = hpke_seal_base(
        pk_r,
        h("4f6465206f6e2061204772656369616e2055726e"),
        h("436f756e742d30"),
        h("4265617574792069732074727574682c20747275746820626561757479"),
        h("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"),
    )
    assert enc == h("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
    assert ct == h(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
        "21993c62ce81883d2dd1b51a28"
    ), "RFC 9180 A.2.1.1 sequence 0"
    out = xchacha20poly1305_seal(
        h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        h("404142434445464748494a4b4c4d4e4f5051525354555657"),
        h(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e"
        ),
        h("50515253c0c1c2c3c4c5c6c7"),
    )
    assert out.hex().endswith("c0875924c1c7987947deafd8780acf49"), "XChaCha draft A.3.1 tag"
    assert out.hex().startswith("bd6d179d3e83d43b9576579493c0e939"), "XChaCha draft A.3.1"
    for low in (
        "00" * 32,
        "01" + "00" * 31,
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ec" + "ff" * 30 + "7f",
    ):
        assert x25519(counting(0x21, 32), h(low)) == b"\x00" * 32, "low order " + low
    okm = hkdf_expand(
        hkdf_extract(h("000102030405060708090a0b0c"), h("0b" * 22)),
        h("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    assert okm == h(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ), "RFC 5869 test case 1"



def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def counting(start, length):
    return bytes((start + i) % 256 for i in range(length))


# ---------------------------------------------------------------------------------------------
# Hangar Drive formats
# ---------------------------------------------------------------------------------------------


def field(data):
    return struct.pack(">I", len(data)) + data


def framed(*parts):
    return b"".join(field(p) for p in parts)


def u16(v):
    return struct.pack(">H", v)


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def i64(v):
    return struct.pack(">q", v)


def label(name):
    return b"hangar-drive/v1/" + name.encode()


def sha256(data):
    return hashlib.sha256(data).digest()


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def padme(length):
    """Padme (Nikitin et al., PETS 2019, algorithm 1)."""
    if length < 2:
        return length
    e = length.bit_length() - 1
    s = e.bit_length()
    last_bits = e - s
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


def safety_number(digest):
    return " ".join(
        "%05d" % (int.from_bytes(digest[5 * i : 5 * i + 5], "big") % 100000) for i in range(6)
    )


ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crockford_code(code_label, entropy):
    payload = b"\x01" + entropy + sha256(framed(label(code_label), b"\x01", entropy))[:3]
    bits = "".join(format(b, "08b") for b in payload)
    chars = [ALPHABET[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5)]
    return "-".join("".join(chars[i : i + 4]) for i in range(0, len(chars), 4))


ACCOUNT = counting(0x10, 16)
DEVICE = counting(0x20, 16)
DEVICE2 = counting(0x29, 16)
SEEDS2 = counting(0x91, 64)
FOLDER = counting(0x30, 16)
SERVER = counting(0x40, 16)
SEEDS = counting(0x50, 64)
EPOCH_SECRET = counting(0x60, 32)
CHALLENGE = counting(0x70, 32)
WRAP_IKM = counting(0x80, 32)
FOLDER_KEY = counting(0xA0, 32)
OBJECT_NONCE = counting(0xB0, 24)
RECORD_NONCE = counting(0xC0, 24)
RECOVERY_ENTROPY = counting(0xD0, 16)
PAIRING_SECRET = counting(0xE0, 16)
SPKI_PIN = counting(0xF0, 32)
ISSUED_AT = 1_700_000_000_000
MTIME = 1_700_000_000_000
EXPIRES = ISSUED_AT + 600_000
FOLDERS_NONCE = counting(0xC8, 24)
NAMES_NONCE = counting(0xD8, 24)
# Names whose case keys differ between the three keys of the name policy (src/vectors.rs).
CASE_NAMES = [
    "CAFÉ",
    "Maſſe ß",
    "ΟΔΟΣ ς",
    "µϐ ﬁ",
    "fıle İ",
    "ǆǄǅ",
]


def nfc(text):
    return unicodedata.normalize("NFC", text)


def case_key(name):
    return nfc(nfc(name).lower())


def fold_key(name):
    """Full case folding (CaseFolding.txt C and F): Python's str.casefold."""
    return nfc(nfc(name).casefold())


def upper_key(name):
    out = []
    for c in nfc(name):
        upper = c.upper()
        out.append(upper if len(upper) == 1 else c)
    return nfc("".join(out))


def format_ranges():
    """General Category Cf, Zl and Zp (the bidirectional controls are all Cf), merged."""
    ranges = []
    for cp in range(0x110000):
        if unicodedata.category(chr(cp)) not in ("Cf", "Zl", "Zp"):
            continue
        if ranges and ranges[-1][1] + 1 == cp:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp])
    return " ".join("%x-%x" % (low, high) for low, high in ranges)


# Display names across every rule of the name policy, checked with a bound of 16 bytes
# (src/vectors.rs).
DISPLAY_NAMES = [
    "Laptop",
    "",
    "seventeen bytes!!",
    "a\u007fb",
    "a‮b",
    " ",
    "　 ",
    "ㅤ",
    "ᅟᅠ ﾠ",
    " Laptop",
    "Laptop ",
    "My Laptop",
    "한ㅤ",
    "ㅤa",
]

# Hangul fillers: letters (Lo) that render blank.
FILLERS = "ᅟᅠㅤﾠ"


def display_verdict(name, max_len):
    """The display name rule: control (Cc), format (Cf, Zl, Zp), blank, padded edge.

    str.isspace and Rust's char::is_whitespace differ only on control characters, which the
    rule refuses first."""
    if not name:
        return "empty"
    if len(name.encode()) > max_len:
        return "too-long"
    if any(unicodedata.category(c) == "Cc" for c in name):
        return "control"
    if any(unicodedata.category(c) in ("Cf", "Zl", "Zp") for c in name):
        return "format"
    if all(c.isspace() or c in FILLERS for c in name):
        return "blank"
    if name[0].isspace() or name[-1].isspace():
        return "edge-whitespace"
    return "ok"


def log_entry(seed, index, prev, issued_at, issuer, kind_fields):
    body = framed(
        label("device-log-entry"), b"\x01", ACCOUNT, u64(index), prev, u64(issued_at), issuer,
    ) + kind_fields
    entry = body + ed25519_sign(seed, body)
    return entry, sha256(framed(label("device-log"), u64(index), prev, entry))


def seal_record(account_key, kind, record_id, version, nonce, plaintext, sign_seed, rotate_hash):
    aad = framed(
        label("record"), b"\x01", ACCOUNT, u32(1), kind, record_id, u64(version), DEVICE,
        u64(2), rotate_hash,
    )
    sealed = xchacha20poly1305_seal(account_key, nonce, plaintext, aad)
    sig = ed25519_sign(sign_seed, framed(label("record-sig"), aad, nonce, sealed))
    header = b"\x01" + u32(1) + u64(version) + DEVICE + u64(2) + rotate_hash + nonce
    return header + sealed + sig


def compute():
    out = {}
    sign_seed, kem_sk = SEEDS[:32], SEEDS[32:]
    sign_pub, kem_pub = ed25519_public(sign_seed), x25519_public(kem_sk)
    out["identity.sign_public"] = sign_pub.hex()
    out["identity.kem_public"] = kem_pub.hex()
    out["identity.safety_number"] = safety_number(
        sha256(framed(label("safety-number"), ACCOUNT, DEVICE, sign_pub, kem_pub))
    )
    proof = ed25519_sign(
        sign_seed, framed(label("device-proof"), ACCOUNT, DEVICE, sign_pub, kem_pub, b"\x00")
    )
    out["identity.proof"] = proof.hex()

    # Device log: create (index 1) and rotate epoch 1 (index 2).
    device = framed(DEVICE, sign_pub, kem_pub, b"\x00", proof)
    body = framed(
        label("device-log-entry"), b"\x01", ACCOUNT, u64(1), b"", u64(ISSUED_AT), DEVICE, b"\x01",
        u32(1),
    ) + device
    create = body + ed25519_sign(sign_seed, body)
    create_hash = sha256(framed(label("device-log"), u64(1), b"", create))
    out["log.create_entry"] = create.hex()
    out["log.create_hash"] = create_hash.hex()
    commitment = sha256(framed(label("epoch-commitment"), ACCOUNT, u32(1), EPOCH_SECRET))
    out["epoch.commitment"] = commitment.hex()
    body = framed(
        label("device-log-entry"), b"\x01", ACCOUNT, u64(2), create_hash, u64(ISSUED_AT + 1),
        DEVICE, b"\x04", u32(1), commitment,
    )
    rotate = body + ed25519_sign(sign_seed, body)
    rotate_hash = sha256(framed(label("device-log"), u64(2), create_hash, rotate))
    out["log.rotate_entry"] = rotate.hex()
    out["log.rotate_hash"] = rotate_hash.hex()
    out["log.safety_number"] = safety_number(
        sha256(framed(label("log-safety-number"), ACCOUNT, u64(2), rotate_hash))
    )

    # The log goes on: a second device is added (index 3) and removed again (index 4).
    sign_seed2, kem_sk2 = SEEDS2[:32], SEEDS2[32:]
    sign_pub2, kem_pub2 = ed25519_public(sign_seed2), x25519_public(kem_sk2)
    proof2 = ed25519_sign(
        sign_seed2, framed(label("device-proof"), ACCOUNT, DEVICE2, sign_pub2, kem_pub2, b"\x00")
    )
    add, add_hash = log_entry(
        sign_seed, 3, rotate_hash, ISSUED_AT + 2, DEVICE,
        framed(b"\x02", DEVICE2, sign_pub2, kem_pub2, b"\x00", proof2),
    )
    out["log.add_entry"] = add.hex()
    out["log.add_hash"] = add_hash.hex()
    remove, remove_hash = log_entry(
        sign_seed, 4, add_hash, ISSUED_AT + 3, DEVICE, framed(b"\x03", DEVICE2)
    )
    out["log.remove_entry"] = remove.hex()
    out["log.remove_hash"] = remove_hash.hex()

    # Epoch: account seal key and the wrapped secret.
    account_key = hkdf(
        EPOCH_SECRET, framed(label("account-seal"), ACCOUNT, u32(1), rotate_hash), 32
    )
    enc, ct = hpke_seal_base(
        kem_pub, framed(label("wrap"), ACCOUNT, u32(1), DEVICE), b"", EPOCH_SECRET, WRAP_IKM
    )
    out["epoch.wrapped_key"] = (b"\x01" + enc + ct).hex()

    # Objects: a chunk, a file manifest and a directory node in generation 1.
    k_obj = hkdf(FOLDER_KEY, framed(label("object-key"), FOLDER, u32(1)), 32)
    k_id = hkdf(FOLDER_KEY, framed(label("object-id"), FOLDER, u32(1)), 32)

    def object_id(kind, plaintext):
        return hmac_sha256(k_id, field(bytes([kind])) + field(plaintext))

    def seal_object(kind, plaintext, nonce):
        oid = object_id(kind, plaintext)
        padded = u64(len(plaintext)) + plaintext
        padded += b"\x00" * (padme(8 + len(plaintext)) - len(padded))
        aad = framed(label("object"), b"\x01", ACCOUNT, FOLDER, u32(1), bytes([kind]), oid)
        return oid, b"\x01" + u32(1) + bytes([kind]) + nonce + xchacha20poly1305_seal(
            k_obj, nonce, padded, aad
        )

    chunk = b"hello, drive"
    chunk_id, chunk_blob = seal_object(1, chunk, OBJECT_NONCE)
    out["object.chunk_id"] = chunk_id.hex()
    out["object.chunk_blob"] = chunk_blob.hex()

    manifest = b"\x01" + u64(len(chunk)) + i64(MTIME) + u32(1) + u32(1) + chunk_id
    out["format.file_manifest"] = manifest.hex()
    manifest_id = object_id(2, manifest)
    out["object.manifest_id"] = manifest_id.hex()

    original = counting(0x01, 16)
    copy = counting(0x02, 16)
    folder_item = counting(0x03, 16)
    empty_node = b"\x01" + u32(0)
    empty_id = object_id(3, empty_node)
    entries = [
        # name, kind, item, child, size, mtime, flags, conflict_of
        ("café.txt", 1, original, manifest_id, len(chunk), MTIME, 1, None),
        ("café (conflict laptop 2026-11-26).txt", 1, copy, manifest_id, len(chunk), MTIME, 0, original),
        ("Docs", 2, folder_item, empty_id, 0, MTIME, 0, None),
    ]
    entries.sort(key=lambda e: unicodedata.normalize("NFC", e[0]).encode())
    node = b"\x01" + u32(len(entries))
    for name, kind, item, child, size, mtime, flags, conflict_of in entries:
        key = unicodedata.normalize("NFC", name)
        wire_flags = flags | (2 if conflict_of else 0)
        node += field(name.encode()) + field(key.encode()) + bytes([kind]) + item + child
        node += u64(size) + i64(mtime) + u32(wire_flags) + (conflict_of or b"")
    out["format.directory_node"] = node.hex()
    root_id = object_id(3, node)
    out["object.root_id"] = root_id.hex()
    out["object.empty_node_id"] = empty_id.hex()

    # Commits: the first commit, then a re-anchor commit on it.
    def commit(height, parents, counter, flags):
        body = framed(
            label("commit"), b"\x01", ACCOUNT, FOLDER, u64(height),
            bytes([len(parents)]) + b"".join(parents), root_id, u32(1), DEVICE, u64(2),
            rotate_hash, u64(counter), u32(flags), b"\x00",
        )
        cid = sha256(field(label("commit-id")) + body)
        sig = ed25519_sign(sign_seed, field(label("commit-sig")) + body)
        return cid, body + sig

    first_id, first_wire = commit(1, [], 1, 0)
    out["commit.first_id"] = first_id.hex()
    out["commit.first_wire"] = first_wire.hex()
    re_id, re_wire = commit(2, [first_id], 2, 1)
    out["commit.reanchor_id"] = re_id.hex()
    out["commit.reanchor_wire"] = re_wire.hex()
    # A side commit (flags bit 1) on the first commit, merged with the re-anchor commit.
    side_id, side_wire = commit(2, [first_id], 3, 2)
    out["commit.side_id"] = side_id.hex()
    out["commit.side_wire"] = side_wire.hex()
    merge_id, merge_wire = commit(3, [re_id, side_id], 4, 0)
    out["commit.merge_id"] = merge_id.hex()
    out["commit.merge_wire"] = merge_wire.hex()
    out["identity.folder_safety_number"] = safety_number(
        sha256(framed(label("folder-safety-number"), ACCOUNT, FOLDER, first_id, u64(1)))
    )

    # Records, each sealed as version 1 under epoch 1: the folder key ring (generation 1
    # created at log index 2), the folder list and the device names.
    ring = b"\x01" + FOLDER + u16(1) + u32(1) + u64(2) + FOLDER_KEY
    out["record.ring_plaintext"] = ring.hex()
    out["record.ring_sealed"] = seal_record(
        account_key, b"folder-keys", FOLDER, 1, RECORD_NONCE, ring, sign_seed, rotate_hash
    ).hex()
    out["record.folder_list"] = (b"\x01" + u32(1) + FOLDER + field(b"Photos")).hex()
    folders = sorted(
        [
            (counting(0x33, 16), "Café \U0001f600"),
            (FOLDER, "Photos"),
            (counting(0x31, 16), "Arbeit"),
        ]
    )
    many = b"\x01" + u32(len(folders))
    for folder_id, name in folders:
        many += folder_id + field(name.encode())
    out["record.folder_list_many"] = many.hex()
    out["record.folders_sealed"] = seal_record(
        account_key, b"folders", b"", 1, FOLDERS_NONCE, many, sign_seed, rotate_hash
    ).hex()
    names = sorted([(DEVICE2, "Laptop"), (DEVICE, "Desktop")])
    name_list = b"\x01" + u32(len(names))
    for device_id, name in names:
        name_list += device_id + field(name.encode())
    out["record.device_names"] = name_list.hex()
    out["record.device_names_sealed"] = seal_record(
        account_key, b"device-names", b"", 1, NAMES_NONCE, name_list, sign_seed, rotate_hash
    ).hex()

    # Recovery code and recovery identity.
    out["recovery.code"] = crockford_code("recovery-code", RECOVERY_ENTROPY)
    okm = hkdf(RECOVERY_ENTROPY, framed(label("recovery-identity")), 64)
    out["recovery.sign_public"] = ed25519_public(okm[:32]).hex()
    out["recovery.kem_public"] = x25519_public(okm[32:]).hex()
    out["recovery.device_id"] = hkdf(RECOVERY_ENTROPY, framed(label("recovery-device-id")), 16).hex()

    # Pairing: code, routing ID, request tag and offer.
    out["pairing.code"] = crockford_code("pairing-code", PAIRING_SECRET)
    out["pairing.id"] = hkdf(PAIRING_SECRET, framed(label("pairing-id")), 16).hex()
    mac_key = hkdf(PAIRING_SECRET, framed(label("pairing-mac")), 32)
    out["pairing.tag"] = hmac_sha256(
        mac_key,
        framed(label("pairing-request"), ACCOUNT, DEVICE, sign_pub, kem_pub, proof, b"Laptop"),
    ).hex()
    # The offer carries the URL in the WHATWG serialization and the inviter's signature.
    offer = b"\x01" + framed(
        b"https://drive.example/", SPKI_PIN, SERVER, ACCOUNT, DEVICE, u64(2), rotate_hash,
        PAIRING_SECRET, u64(EXPIRES),
    )
    offer_sig = ed25519_sign(sign_seed, field(label("pairing-offer")) + offer)
    out["pairing.offer"] = (offer + offer_sig).hex()

    # Session proof and server key number.
    out["session.proof"] = ed25519_sign(
        sign_seed,
        framed(label("session-proof"), SERVER, ACCOUNT, DEVICE, sign_pub, CHALLENGE, u16(1)),
    ).hex()
    out["identity.server_key_number"] = safety_number(
        sha256(framed(label("server-key-number"), SERVER, SPKI_PIN))
    )

    # Name policy and padding.
    out["name.comparison_key"] = unicodedata.normalize("NFC", "café").encode().hex()
    out["name.case_key"] = case_key("CAFÉ").encode().hex()
    out["name.case_keys"] = " ".join(case_key(n).encode().hex() for n in CASE_NAMES)
    out["name.fold_keys"] = " ".join(fold_key(n).encode().hex() for n in CASE_NAMES)
    out["name.upper_keys"] = " ".join(upper_key(n).encode().hex() for n in CASE_NAMES)
    out["name.format_ranges"] = format_ranges()
    out["name.display_names"] = " ".join(display_verdict(n, 16) for n in DISPLAY_NAMES)
    out["padme"] = " ".join(
        "%d:%d" % (n, padme(n)) for n in (8, 9, 15, 17, 100, 1000, 1025, 65544, 4194312)
    )
    return out


def main():
    # The name policy's tables (FORMAT_CHARACTER_RANGES, case folding) are Unicode 16.0, and
    # unicodedata follows the Python release (3.12 has 15.0, 3.14 has 16.0): another version
    # would report a difference that is not one.
    if unicodedata.unidata_version != UNICODE_VERSION:
        sys.exit(
            "needs Unicode %s in unicodedata (Python 3.14), this Python has %s"
            % (UNICODE_VERSION, unicodedata.unidata_version)
        )
    check_anchors()
    print(
        "anchors: RFC 8032, RFC 7748, RFC 9180 A.2.1, XChaCha draft A.3.1, RFC 5869, "
        "X25519 low-order points ok"
    )
    computed = compute()
    if "--write" in sys.argv[1:]:
        # LF on every platform (.gitattributes), so the file is identical wherever it is written.
        VECTORS.write_text(
            json.dumps(computed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        print("wrote %d vectors to %s" % (len(computed), VECTORS))
        return
    stored = json.loads(VECTORS.read_text(encoding="utf-8"))
    failed = False
    for name in sorted(set(computed) | set(stored)):
        if computed.get(name) != stored.get(name):
            print("%s differs:\n  computed %s\n  stored   %s" % (name, computed.get(name), stored.get(name)))
            failed = True
    if failed:
        sys.exit(1)
    print("all %d vectors match" % len(computed))


if __name__ == "__main__":
    main()
