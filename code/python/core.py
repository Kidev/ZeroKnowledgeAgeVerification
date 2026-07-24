"""
core.py - cryptographic core: field, hash, accumulator, proof system.

Primitives:
  Field        Goldilocks prime p = 2^64 - 2^32 + 1
  Permutation  Poseidon2, t = 8, d = 7, RF = 8, RP = 22, with the
               official round constants and internal matrix published
               by the Poseidon2 authors (HorizenLabs reference
               implementation). perm_native is generic in the state
               width, so test_core.py runs the designers' t = 12
               known-answer vector through this exact routine
  Digests      4 field elements (256 bits): 128-bit collision
               resistance, 128-bit PQ preimage resistance (Grover)
  Merkle tree  sparse incremental tree, default depth 32 (4.29 billion
               leaf capacity), Poseidon2 compression mode
               C(l, r) = Trunc_4(P(l || r) + (l || r))
  NIZK         ZKBoo (MPC-in-the-head, Giacomelli-Madsen-Orlandi 2016)
               over the arithmetic circuit of the membership + PRF
               statement, Fiat-Shamir with SHA3-256, default 219
               repetitions: soundness error (2/3)^219 < 2^-128

Wire-format domain separators use the neutral tag "avsm" (anonymous
verified set membership). Every multi-byte integer on the wire and in
every hash input is little-endian regardless of host byte order, so the
format is a specification rather than an artifact of x86.

The statement proven:
  "I know secret s in F^4 and a Merkle path such that
     LeafHash(s) is a leaf under the public root, and
     temp_key = PRF(s, ctx)   for the public ctx = H(domain, epoch)"
transcript-bound to (domain, epoch, root, temp_key, website nonce).

Replay resistance (paper, Theorem 4) needs the map from that tuple to
the ctx_bytes handed to prove/verify to be injective. core does not
build ctx_bytes; protocol.token_context_bytes does, and enforces the
condition there.
"""

import hashlib
import secrets
import struct
import sys
from array import array

from poseidon2_constants import MAT_DIAG8_M_1, RC8

# Field

P = (1 << 64) - (1 << 32) + 1  # Goldilocks

VERSION = b"avsm/1"
T = 8
RF_HALF = 4
RP = 22
DEFAULT_REPS = 219    # (2/3)^219 < 2^-128
DEFAULT_DEPTH = 32

# Three distinct domain-separation tags. Theorem 1's step 4 needs
# TAG_LEAF != TAG_EMPTY: a proof whose path lands on an unused slot is
# then a collision between two distinct permutation inputs, not a
# legitimate membership witness.
TAG_LEAF = 0x6C656166   # "leaf"
TAG_KEY = 0x707266      # "prf"
TAG_EMPTY = 0x656D7079  # "empy"
assert len({TAG_LEAF, TAG_KEY, TAG_EMPTY}) == 3

# Sanity limits for untrusted wire input. A decoder that trusts the
# header's depth and repetition count can be made to allocate
# arbitrarily much memory before it ever looks at the payload.
MAX_DEPTH = 64
MAX_REPS = 4096


def _u64s_le(vals) -> bytes:
    """Little-endian serialization of a u64 sequence, host independent."""
    a = vals if isinstance(vals, array) and vals.typecode == "Q" \
        else array("Q", vals)
    if sys.byteorder != "little":
        a = array("Q", a)
        a.byteswap()
    return a.tobytes()


def _u64s_from_le(data: bytes, n: int):
    if len(data) < 8 * n:
        raise ValueError("truncated u64 block")
    a = array("Q")
    a.frombytes(data[:8 * n])
    if sys.byteorder != "little":
        a.byteswap()
    return a


def rand_field() -> int:
    while True:
        v = int.from_bytes(secrets.token_bytes(8), "little")
        if v < P:
            return v


def rand_digest():
    return tuple(rand_field() for _ in range(4))


def ser_digest(d) -> bytes:
    return struct.pack("<4Q", *d)


def digest_hex(d) -> str:
    return ser_digest(d).hex()

# Poseidon2 permutation, native fast path

def _matmul_m4(x, t):
    for k in range(0, t, 4):
        x0, x1, x2, x3 = x[k], x[k + 1], x[k + 2], x[k + 3]
        t0 = (x0 + x1) % P
        t1 = (x2 + x3) % P
        t2 = (2 * x1 + t1) % P
        t3 = (2 * x3 + t0) % P
        t4 = (4 * t1 + t3) % P
        t5 = (4 * t0 + t2) % P
        x[k] = (t3 + t5) % P
        x[k + 1] = t5
        x[k + 2] = (t2 + t4) % P
        x[k + 3] = t4


def _matmul_external(x, t):
    _matmul_m4(x, t)
    nblocks = t // 4
    for l in range(4):
        s = 0
        for j in range(nblocks):
            s += x[4 * j + l]
        s %= P
        for j in range(nblocks):
            x[4 * j + l] = (x[4 * j + l] + s) % P


def _sbox(v):
    v2 = v * v % P
    v4 = v2 * v2 % P
    return v4 * v2 % P * v % P


def perm_native(state, rc=RC8, diag=MAT_DIAG8_M_1, rp=RP):
    """Poseidon2, generic in the state width t = len(state) (a multiple
    of 4). Defaults are the t = 8 instance the protocol uses; passing
    the t = 12 constants runs the designers' published known-answer
    vector through this same routine (see test_core.py)."""
    t = len(state)
    x = list(state)
    _matmul_external(x, t)
    for r in range(RF_HALF):
        rcr = rc[r]
        x = [_sbox((x[i] + rcr[i]) % P) for i in range(t)]
        _matmul_external(x, t)
    for r in range(RF_HALF, RF_HALF + rp):
        x[0] = _sbox((x[0] + rc[r][0]) % P)
        s = sum(x) % P
        x = [(x[i] * diag[i] + s) % P for i in range(t)]
    for r in range(RF_HALF + rp, RF_HALF + rp + RF_HALF):
        rcr = rc[r]
        x = [_sbox((x[i] + rcr[i]) % P) for i in range(t)]
        _matmul_external(x, t)
    return x


def leaf_hash_native(s):
    st = perm_native([s[0], s[1], s[2], s[3], TAG_LEAF, 0, 0, 0])
    return tuple(st[:4])


def compress_native(l, r):
    inp = [l[0], l[1], l[2], l[3], r[0], r[1], r[2], r[3]]
    st = perm_native(inp)
    return tuple((st[i] + inp[i]) % P for i in range(4))  # feed-forward


def prf_native(s, ctx):
    st = perm_native([s[0], s[1], s[2], s[3], TAG_KEY, 0, 0, 0])
    st = [(st[i] + ctx[i]) % P if i < 4 else st[i] for i in range(T)]
    st = perm_native(st)
    return tuple(st[:4])


def context_digest(domain: str, epoch: int):
    raw = hashlib.shake_256(
        b"avsm-ctx/1|" + domain.encode() + b"|"
        + struct.pack("<Q", epoch)).digest(64)
    out, off = [], 0
    while len(out) < 4:
        v = int.from_bytes(raw[off:off + 8], "little")
        off += 8
        if off > 56:
            raw += hashlib.shake_256(raw).digest(64)
        if v < P:
            out.append(v)
    return tuple(out)


EMPTY_LEAF = tuple(perm_native([0, 0, 0, 0, TAG_EMPTY, 0, 0, 0])[:4])

# Sparse incremental Merkle tree (Semaphore-style, zero-subtree cache)

class SparseMerkleTree:
    def __init__(self, depth=DEFAULT_DEPTH):
        self.depth = depth
        self.nodes = {}          # (level, index) -> digest; level 0 = leaves
        self.next_index = 0
        self.zero = [EMPTY_LEAF]
        for _ in range(depth):
            z = self.zero[-1]
            self.zero.append(compress_native(z, z))

    def set_leaf(self, idx: int, digest):
        self.nodes[(0, idx)] = tuple(digest)
        cur = idx
        for h in range(self.depth):
            sib = self.nodes.get((h, cur ^ 1), self.zero[h])
            me = self.nodes[(h, cur)]
            l, r = (me, sib) if cur % 2 == 0 else (sib, me)
            cur >>= 1
            self.nodes[(h + 1, cur)] = compress_native(l, r)

    def append(self, digest) -> int:
        idx = self.next_index
        if idx >= (1 << self.depth):
            raise ValueError("tree full")
        self.next_index += 1
        self.set_leaf(idx, digest)
        return idx

    def revoke(self, idx: int):
        self.set_leaf(idx, EMPTY_LEAF)

    def root(self):
        return self.nodes.get((self.depth, 0), self.zero[self.depth])

    def path(self, idx: int):
        bits, sibs = [], []
        cur = idx
        for h in range(self.depth):
            bits.append(cur & 1)
            sibs.append(self.nodes.get((h, cur ^ 1), self.zero[h]))
            cur >>= 1
        return bits, sibs

# Circuit engines

class NativeEngine:
    def const(self, c): return c % P
    def add(self, a, b): return (a + b) % P
    def sub(self, a, b): return (a - b) % P
    def add_c(self, a, c): return (a + c) % P
    def mul_c(self, a, c): return (a * c) % P
    def mul(self, a, b): return (a * b) % P


class ProverEngine:
    """Values are 3-tuples of additive shares. Mask randomness for mult
    gate g is tape[nw + g] on each party's tape. Mult output shares are
    appended to per-party u64 arrays."""

    def __init__(self, tapes, mask_offset):
        self.t0, self.t1, self.t2 = tapes
        self.i = mask_offset
        self.m0 = array("Q")
        self.m1 = array("Q")
        self.m2 = array("Q")

    def const(self, c): return (c % P, 0, 0)
    def add(self, a, b): return ((a[0]+b[0]) % P, (a[1]+b[1]) % P, (a[2]+b[2]) % P)
    def sub(self, a, b): return ((a[0]-b[0]) % P, (a[1]-b[1]) % P, (a[2]-b[2]) % P)
    def add_c(self, a, c): return ((a[0]+c) % P, a[1], a[2])
    def mul_c(self, a, c): return (a[0]*c % P, a[1]*c % P, a[2]*c % P)

    def mul(self, a, b):
        i = self.i
        self.i = i + 1
        r0, r1, r2 = self.t0[i], self.t1[i], self.t2[i]
        a0, a1, a2 = a
        b0, b1, b2 = b
        z0 = (a0*b0 + a1*b0 + a0*b1 + r0 - r1) % P
        z1 = (a1*b1 + a2*b1 + a1*b2 + r1 - r2) % P
        z2 = (a2*b2 + a0*b2 + a2*b0 + r2 - r0) % P
        self.m0.append(z0)
        self.m1.append(z1)
        self.m2.append(z2)
        return (z0, z1, z2)


class PairEngine:
    """Verifier: recomputes party e, consumes party f = e+1's committed
    mult outputs. Raises ValueError on malformed views."""

    def __init__(self, e, tape_e, tape_f, mults_f, mask_offset):
        self.e = e
        self.f = (e + 1) % 3
        self.te = tape_e
        self.tf = tape_f
        self.mf = mults_f
        self.i = mask_offset
        self.j = 0
        self.me = array("Q")

    def const(self, c):
        return (c % P if self.e == 0 else 0, c % P if self.f == 0 else 0)

    def add(self, a, b): return ((a[0]+b[0]) % P, (a[1]+b[1]) % P)
    def sub(self, a, b): return ((a[0]-b[0]) % P, (a[1]-b[1]) % P)

    def add_c(self, a, c):
        return ((a[0]+c) % P if self.e == 0 else a[0],
                (a[1]+c) % P if self.f == 0 else a[1])

    def mul_c(self, a, c): return (a[0]*c % P, a[1]*c % P)

    def mul(self, a, b):
        i = self.i
        self.i = i + 1
        if self.j >= len(self.mf):
            raise ValueError("view too short")
        ze = (a[0]*b[0] + a[1]*b[0] + a[0]*b[1] + self.te[i] - self.tf[i]) % P
        zf = self.mf[self.j]
        self.j += 1
        self.me.append(ze)
        return (ze, zf)

# The circuit (engine-generic)

def _perm_eng(eng, x):
    add, sub, add_c, mul_c, mul = eng.add, eng.sub, eng.add_c, eng.mul_c, eng.mul

    def m4(x, k):
        x0, x1, x2, x3 = x[k], x[k+1], x[k+2], x[k+3]
        t0 = add(x0, x1)
        t1 = add(x2, x3)
        t2 = add(add(x1, x1), t1)
        t3 = add(add(x3, x3), t0)
        t4 = add(add(add(t1, t1), add(t1, t1)), t3)
        t5 = add(add(add(t0, t0), add(t0, t0)), t2)
        x[k] = add(t3, t5)
        x[k+1] = t5
        x[k+2] = add(t2, t4)
        x[k+3] = t4

    def ext(x):
        m4(x, 0)
        m4(x, 4)
        for l in range(4):
            s = add(x[l], x[4+l])
            x[l] = add(x[l], s)
            x[4+l] = add(x[4+l], s)

    def sbox(v):
        v2 = mul(v, v)
        v4 = mul(v2, v2)
        return mul(mul(v4, v2), v)

    x = list(x)
    ext(x)
    for r in range(RF_HALF):
        rc = RC8[r]
        x = [sbox(add_c(x[i], rc[i])) for i in range(T)]
        ext(x)
    for r in range(RF_HALF, RF_HALF + RP):
        x[0] = sbox(add_c(x[0], RC8[r][0]))
        s = x[0]
        for i in range(1, T):
            s = add(s, x[i])
        x = [add(mul_c(x[i], MAT_DIAG8_M_1[i]), s) for i in range(T)]
    for r in range(RF_HALF + RP, RF_HALF + RP + RF_HALF):
        rc = RC8[r]
        x = [sbox(add_c(x[i], rc[i])) for i in range(T)]
        ext(x)
    return x


def circuit(eng, ctx, depth, wit):
    """wit: [s0..s3, bit_0, sib_0[0..3], ..., bit_{d-1}, sib_{d-1}[0..3]]
    outputs: temp_key[0..3], root[0..3], bit_check_0..bit_check_{d-1}"""
    zero = eng.const(0)
    s = wit[0:4]

    st = _perm_eng(eng, [s[0], s[1], s[2], s[3],
                         eng.const(TAG_LEAF), zero, zero, zero])
    cur = st[:4]

    bit_checks = []
    off = 4
    for _ in range(depth):
        b = wit[off]
        sib = wit[off + 1:off + 5]
        off += 5
        left, right = [], []
        for i in range(4):
            m = eng.mul(b, eng.sub(sib[i], cur[i]))
            li = eng.add(cur[i], m)               # b ? sib : cur
            left.append(li)
            right.append(eng.sub(eng.add(cur[i], sib[i]), li))
        inp = left + right
        st = _perm_eng(eng, inp)
        cur = [eng.add(st[i], inp[i]) for i in range(4)]  # feed-forward
        bit_checks.append(eng.sub(eng.mul(b, b), b))

    st = _perm_eng(eng, [s[0], s[1], s[2], s[3],
                         eng.const(TAG_KEY), zero, zero, zero])
    st = [eng.add_c(st[i], ctx[i]) if i < 4 else st[i] for i in range(T)]
    st = _perm_eng(eng, st)
    tk = st[:4]

    return list(tk) + list(cur) + bit_checks


def num_witness(depth): return 4 + 5 * depth
def num_outputs(depth): return 8 + depth
def num_muls(depth): return 344 * (3 + depth) + 5 * depth

# Batched tape expansion (SHAKE256 counter mode, rejection sampling)

def expand_tape(seed: bytes, n: int):
    out = []
    ctr = 0
    while len(out) < n:
        need = n - len(out)
        raw = hashlib.shake_256(
            seed + b"|tape|" + struct.pack("<I", ctr)).digest((need + 32) * 8)
        vals = struct.unpack("<%dQ" % (len(raw) // 8), raw)
        out.extend(v for v in vals if v < P)
        ctr += 1
    return out[:n]

# ZKBoo prover / verifier

def _commit(seed: bytes, extra: bytes, mults) -> bytes:
    h = hashlib.sha3_256()
    h.update(b"avsm-com/1|")
    h.update(seed)
    h.update(extra)
    h.update(_u64s_le(mults))
    return h.digest()


def _transcript_hash(ctx_bytes: bytes, reps) -> bytes:
    h = hashlib.sha3_256()
    h.update(b"avsm-fs/1|")
    h.update(VERSION)
    h.update(ctx_bytes)
    for rep in reps:
        for c in rep["commits"]:
            h.update(c)
        for outs in rep["outs"]:
            h.update(_u64s_le(outs))
    return h.digest()


def _challenges(th: bytes, nreps: int):
    trits, ctr = [], 0
    while len(trits) < nreps:
        blk = hashlib.shake_256(
            th + b"|chal|" + struct.pack("<I", ctr)).digest(64)
        ctr += 1
        for byte in blk:
            if byte < 255:              # unbiased mod 3
                trits.append(byte % 3)
                if len(trits) == nreps:
                    break
    return trits


def prove(witness, ctx, depth, ctx_bytes, nreps=DEFAULT_REPS):
    nw = num_witness(depth)
    nm = num_muls(depth)
    assert len(witness) == nw
    tape_len = nw + nm

    reps, priv = [], []
    for _ in range(nreps):
        seeds = [secrets.token_bytes(32) for _ in range(3)]
        t0 = expand_tape(seeds[0], tape_len)
        t1 = expand_tape(seeds[1], tape_len)
        t2 = expand_tape(seeds[2], tape_len)
        # input shares of parties 0 and 1 are their tape prefixes;
        # party 2's shares complete the sharing and are committed explicitly
        inputs2 = array("Q", ((witness[k] - t0[k] - t1[k]) % P
                              for k in range(nw)))
        shared = [(t0[k], t1[k], inputs2[k]) for k in range(nw)]
        eng = ProverEngine((t0, t1, t2), nw)
        outs = circuit(eng, ctx, depth, shared)
        outs_by_party = [array("Q", (o[i] for o in outs)) for i in range(3)]
        commits = [
            _commit(seeds[0], b"", eng.m0),
            _commit(seeds[1], b"", eng.m1),
            _commit(seeds[2], inputs2.tobytes(), eng.m2),
        ]
        reps.append({"commits": commits, "outs": outs_by_party})
        priv.append({"seeds": seeds, "inputs2": inputs2,
                     "mults": (eng.m0, eng.m1, eng.m2)})

    th = _transcript_hash(ctx_bytes, reps)
    trits = _challenges(th, nreps)

    openings = []
    for k, e in enumerate(trits):
        f = (e + 1) % 3
        pk = priv[k]
        op = {"seed_e": pk["seeds"][e], "seed_f": pk["seeds"][f],
              "mults_f": pk["mults"][f]}
        if 2 in (e, f):
            op["inputs2"] = pk["inputs2"]
        openings.append(op)
    return {"version": VERSION.decode(), "depth": depth, "nreps": nreps,
            "reps": reps, "openings": openings}


def _canonical(vals, n) -> bool:
    """n field elements, each already reduced. Checked before any value
    reaches a hash input, so the verifier never raises on junk."""
    try:
        if len(vals) != n:
            return False
    except TypeError:
        return False
    for v in vals:
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < P:
            return False
    return True


def verify(proof, ctx, depth, ctx_bytes, expected_outputs,
           nreps=DEFAULT_REPS):
    """Total: returns False on any malformed input, never raises."""
    try:
        if not isinstance(proof, dict):
            return False
        if proof.get("version") != VERSION.decode():
            return False
        if proof.get("depth") != depth or proof.get("nreps") != nreps:
            return False
        if not isinstance(depth, int) or not 1 <= depth <= MAX_DEPTH:
            return False
        if not isinstance(nreps, int) or not 1 <= nreps <= MAX_REPS:
            return False
        reps, openings = proof["reps"], proof["openings"]
        if len(reps) != nreps or len(openings) != nreps:
            return False
        nw = num_witness(depth)
        nm = num_muls(depth)
        nout = num_outputs(depth)
        tape_len = nw + nm
        if not _canonical(ctx, 4):
            return False
        if not _canonical(expected_outputs, nout):
            return False
        expected = list(expected_outputs)

        # Structural validation of everything the transcript hash will
        # absorb, before it absorbs any of it.
        for rep in reps:
            commits = rep["commits"]
            if len(commits) != 3:
                return False
            if any(not isinstance(c, (bytes, bytearray)) or len(c) != 32
                   for c in commits):
                return False
            outs = rep["outs"]
            if len(outs) != 3 or any(not _canonical(o, nout) for o in outs):
                return False

        th = _transcript_hash(ctx_bytes, reps)
        trits = _challenges(th, nreps)

        for k in range(nreps):
            e = trits[k]
            f = (e + 1) % 3
            rep, op = reps[k], openings[k]

            outs = rep["outs"]
            for j in range(nout):
                if (outs[0][j] + outs[1][j] + outs[2][j]) % P != expected[j]:
                    return False

            seed_e, seed_f = op["seed_e"], op["seed_f"]
            if any(not isinstance(s, (bytes, bytearray)) or len(s) != 32
                   for s in (seed_e, seed_f)):
                return False
            mults_f = op["mults_f"]
            if not _canonical(mults_f, nm):
                return False

            inputs2 = op.get("inputs2")
            if 2 in (e, f):
                if not _canonical(inputs2, nw):
                    return False
                extra2 = _u64s_le(inputs2)
            else:
                extra2 = b""

            tape_e = expand_tape(seed_e, tape_len)
            tape_f = expand_tape(seed_f, tape_len)
            shared = [(tape_e[kk] if e < 2 else inputs2[kk],
                       tape_f[kk] if f < 2 else inputs2[kk])
                      for kk in range(nw)]

            eng = PairEngine(e, tape_e, tape_f, mults_f, nw)
            pouts = circuit(eng, ctx, depth, shared)
            if eng.j != nm:
                return False

            extra_e = extra2 if e == 2 else b""
            extra_f = extra2 if f == 2 else b""
            if _commit(seed_e, extra_e, eng.me) != rep["commits"][e]:
                return False
            if _commit(seed_f, extra_f, mults_f) != rep["commits"][f]:
                return False

            for j in range(nout):
                if pouts[j][0] != outs[e][j] or pouts[j][1] != outs[f][j]:
                    return False
        return True
    except Exception:
        # A verifier that raises is a verifier an attacker can turn into
        # a denial of service; any surprise here is a rejection.
        return False

# Binary wire format

MAGIC = b"AVSM"
HEADER_LEN = len(MAGIC) + len(VERSION) + 6


def proof_to_bytes(proof) -> bytes:
    out = [MAGIC, VERSION, struct.pack("<HI", proof["depth"],
                                       proof["nreps"])]
    for rep in proof["reps"]:
        for c in rep["commits"]:
            out.append(c)
        for o in rep["outs"]:
            out.append(_u64s_le(o))
    for op in proof["openings"]:
        out.append(op["seed_e"])
        out.append(op["seed_f"])
        has2 = "inputs2" in op
        out.append(b"\x01" if has2 else b"\x00")
        if has2:
            out.append(_u64s_le(op["inputs2"]))
        out.append(_u64s_le(op["mults_f"]))
    return b"".join(out)


def proof_from_bytes(data: bytes):
    """Raises ValueError on anything that is not a well-formed blob.
    The header is bounds-checked before any allocation is sized from
    it, so a short hostile blob cannot request gigabytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("not a byte string")
    if len(data) < HEADER_LEN or data[:4] != MAGIC:
        raise ValueError("bad magic")
    off = 4 + len(VERSION)
    if data[4:off] != VERSION:
        raise ValueError("bad version")
    depth, nreps = struct.unpack_from("<HI", data, off)
    off += 6
    if not 1 <= depth <= MAX_DEPTH or not 1 <= nreps <= MAX_REPS:
        raise ValueError("header out of range")
    nout = num_outputs(depth)
    nw = num_witness(depth)
    nm = num_muls(depth)

    # Reject on declared size before allocating anything from it.
    body = len(data) - HEADER_LEN
    per_rep = 96 + 3 * 8 * nout
    per_open_min = 64 + 1 + 8 * nm
    lo = nreps * (per_rep + per_open_min)
    hi = lo + nreps * 8 * nw
    if not lo <= body <= hi:
        raise ValueError("declared header inconsistent with blob length")

    reps = []
    for _ in range(nreps):
        commits = [bytes(data[off:off + 32]), bytes(data[off + 32:off + 64]),
                   bytes(data[off + 64:off + 96])]
        off += 96
        outs = []
        for _ in range(3):
            outs.append(_u64s_from_le(data[off:off + 8 * nout], nout))
            off += 8 * nout
        reps.append({"commits": commits, "outs": outs})
    openings = []
    for _ in range(nreps):
        op = {"seed_e": bytes(data[off:off + 32]),
              "seed_f": bytes(data[off + 32:off + 64])}
        off += 64
        if off >= len(data):
            raise ValueError("truncated opening")
        has2 = data[off]
        off += 1
        if has2 not in (0, 1):
            raise ValueError("bad inputs2 flag")
        if has2:
            op["inputs2"] = _u64s_from_le(data[off:off + 8 * nw], nw)
            off += 8 * nw
        op["mults_f"] = _u64s_from_le(data[off:off + 8 * nm], nm)
        off += 8 * nm
        openings.append(op)
    if off != len(data):
        raise ValueError("trailing bytes")
    return {"version": VERSION.decode(), "depth": depth, "nreps": nreps,
            "reps": reps, "openings": openings}
