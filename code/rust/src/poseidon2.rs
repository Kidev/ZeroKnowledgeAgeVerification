// Poseidon2 native fast path plus the three domain separated functions
// and the sparse incremental Merkle tree, mirroring code/core.py.

use crate::constants::{MAT_DIAG8_M_1, RC8};
use crate::field::{add, mul, P};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::HashMap;

pub const T: usize = 8;
pub const RF_HALF: usize = 4;
pub const RP: usize = 22;

pub const TAG_LEAF: u64 = 0x6C65_6166;
pub const TAG_KEY: u64 = 0x70_7266;
pub const TAG_EMPTY: u64 = 0x656D_7079;

pub type Digest = [u64; 4];

fn matmul_m4(x: &mut [u64; T]) {
    for k in [0usize, 4] {
        let (x0, x1, x2, x3) = (x[k], x[k + 1], x[k + 2], x[k + 3]);
        let t0 = add(x0, x1);
        let t1 = add(x2, x3);
        let t2 = add(add(x1, x1), t1);
        let t3 = add(add(x3, x3), t0);
        let t4 = add(add(add(t1, t1), add(t1, t1)), t3);
        let t5 = add(add(add(t0, t0), add(t0, t0)), t2);
        x[k] = add(t3, t5);
        x[k + 1] = t5;
        x[k + 2] = add(t2, t4);
        x[k + 3] = t4;
    }
}

fn matmul_external(x: &mut [u64; T]) {
    matmul_m4(x);
    for l in 0..4 {
        let s = add(x[l], x[4 + l]);
        x[l] = add(x[l], s);
        x[4 + l] = add(x[4 + l], s);
    }
}

#[inline(always)]
fn sbox(v: u64) -> u64 {
    let v2 = mul(v, v);
    let v4 = mul(v2, v2);
    mul(mul(v4, v2), v)
}

pub fn perm_native(state: &[u64; T]) -> [u64; T] {
    let mut x = *state;
    matmul_external(&mut x);
    for rc in &RC8[0..RF_HALF] {
        for i in 0..T {
            x[i] = sbox(add(x[i], rc[i]));
        }
        matmul_external(&mut x);
    }
    for rc in &RC8[RF_HALF..RF_HALF + RP] {
        x[0] = sbox(add(x[0], rc[0]));
        let s = x.iter().fold(0u64, |acc, &v| add(acc, v));
        for i in 0..T {
            x[i] = add(mul(x[i], MAT_DIAG8_M_1[i]), s);
        }
    }
    for rc in &RC8[RF_HALF + RP..RF_HALF + RP + RF_HALF] {
        for i in 0..T {
            x[i] = sbox(add(x[i], rc[i]));
        }
        matmul_external(&mut x);
    }
    x
}

pub fn leaf_hash_native(s: &Digest) -> Digest {
    let st = perm_native(&[s[0], s[1], s[2], s[3], TAG_LEAF, 0, 0, 0]);
    [st[0], st[1], st[2], st[3]]
}

pub fn compress_native(l: &Digest, r: &Digest) -> Digest {
    let inp = [l[0], l[1], l[2], l[3], r[0], r[1], r[2], r[3]];
    let st = perm_native(&inp);
    [
        add(st[0], inp[0]),
        add(st[1], inp[1]),
        add(st[2], inp[2]),
        add(st[3], inp[3]),
    ]
}

pub fn prf_native(s: &Digest, ctx: &Digest) -> Digest {
    let mut st = perm_native(&[s[0], s[1], s[2], s[3], TAG_KEY, 0, 0, 0]);
    for i in 0..4 {
        st[i] = add(st[i], ctx[i]);
    }
    let st = perm_native(&st);
    [st[0], st[1], st[2], st[3]]
}

pub fn empty_leaf() -> Digest {
    let st = perm_native(&[0, 0, 0, 0, TAG_EMPTY, 0, 0, 0]);
    [st[0], st[1], st[2], st[3]]
}

// SHAKE256 with rejection sampling, byte compatible with
// core.context_digest including its buffer extension rule.
pub fn context_digest(domain: &str, epoch: u64) -> Digest {
    let mut h = Shake256::default();
    h.update(b"avsm-ctx/1|");
    h.update(domain.as_bytes());
    h.update(b"|");
    h.update(&epoch.to_le_bytes());
    let mut raw = vec![0u8; 64];
    h.finalize_xof().read(&mut raw);

    let mut out = [0u64; 4];
    let mut n = 0usize;
    let mut off = 0usize;
    while n < 4 {
        let v = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        if off > 56 {
            let mut h2 = Shake256::default();
            h2.update(&raw);
            let mut ext = vec![0u8; 64];
            h2.finalize_xof().read(&mut ext);
            raw.extend_from_slice(&ext);
        }
        if v < P {
            out[n] = v;
            n += 1;
        }
    }
    out
}

pub fn ser_digest(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&d[i].to_le_bytes());
    }
    out
}

// Sparse incremental Merkle tree with cached empty subtree digests.
pub struct SparseMerkleTree {
    pub depth: usize,
    nodes: HashMap<(usize, u64), Digest>,
    pub next_index: u64,
    zero: Vec<Digest>,
}

impl SparseMerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zero = vec![empty_leaf()];
        for _ in 0..depth {
            let z = *zero.last().unwrap();
            zero.push(compress_native(&z, &z));
        }
        Self {
            depth,
            nodes: HashMap::new(),
            next_index: 0,
            zero,
        }
    }

    pub fn set_leaf(&mut self, idx: u64, digest: Digest) {
        self.nodes.insert((0, idx), digest);
        let mut cur = idx;
        for h in 0..self.depth {
            let sib = *self.nodes.get(&(h, cur ^ 1)).unwrap_or(&self.zero[h]);
            let me = self.nodes[&(h, cur)];
            let (l, r) = if cur.is_multiple_of(2) {
                (me, sib)
            } else {
                (sib, me)
            };
            cur >>= 1;
            self.nodes.insert((h + 1, cur), compress_native(&l, &r));
        }
    }

    pub fn append(&mut self, digest: Digest) -> u64 {
        let idx = self.next_index;
        assert!(self.depth >= 64 || idx < 1u64 << self.depth, "tree full");
        self.next_index += 1;
        self.set_leaf(idx, digest);
        idx
    }

    pub fn root(&self) -> Digest {
        *self
            .nodes
            .get(&(self.depth, 0))
            .unwrap_or(&self.zero[self.depth])
    }

    pub fn path(&self, idx: u64) -> (Vec<u64>, Vec<Digest>) {
        let mut bits = Vec::with_capacity(self.depth);
        let mut sibs = Vec::with_capacity(self.depth);
        let mut cur = idx;
        for h in 0..self.depth {
            bits.push(cur & 1);
            sibs.push(*self.nodes.get(&(h, cur ^ 1)).unwrap_or(&self.zero[h]));
            cur >>= 1;
        }
        (bits, sibs)
    }
}
