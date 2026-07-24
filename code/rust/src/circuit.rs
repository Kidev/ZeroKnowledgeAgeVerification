// Engine generic circuit of the membership + PRF statement, gate order
// identical to code/core.py so tapes, views, and commitments match.

use crate::constants::{MAT_DIAG8_M_1, RC8};
use crate::field::{add, mul, sub, P};
use crate::poseidon2::{RF_HALF, RP, T, TAG_KEY, TAG_LEAF};

pub trait Engine {
    type V: Clone;
    fn cst(&mut self, c: u64) -> Self::V;
    fn add(&mut self, a: &Self::V, b: &Self::V) -> Self::V;
    fn sub(&mut self, a: &Self::V, b: &Self::V) -> Self::V;
    fn add_c(&mut self, a: &Self::V, c: u64) -> Self::V;
    fn mul_c(&mut self, a: &Self::V, c: u64) -> Self::V;
    fn mul(&mut self, a: &Self::V, b: &Self::V) -> Self::V;
}

pub struct NativeEngine;

impl Engine for NativeEngine {
    type V = u64;
    fn cst(&mut self, c: u64) -> u64 {
        c % P
    }
    fn add(&mut self, a: &u64, b: &u64) -> u64 {
        add(*a, *b)
    }
    fn sub(&mut self, a: &u64, b: &u64) -> u64 {
        sub(*a, *b)
    }
    fn add_c(&mut self, a: &u64, c: u64) -> u64 {
        add(*a, c)
    }
    fn mul_c(&mut self, a: &u64, c: u64) -> u64 {
        mul(*a, c)
    }
    fn mul(&mut self, a: &u64, b: &u64) -> u64 {
        mul(*a, *b)
    }
}

// Values are 3-tuples of additive shares. Mult gate g draws mask
// randomness tape[mask_offset + g] on each party's tape; output shares
// are appended to per party views.
pub struct ProverEngine<'a> {
    pub t0: &'a [u64],
    pub t1: &'a [u64],
    pub t2: &'a [u64],
    pub i: usize,
    pub m0: Vec<u64>,
    pub m1: Vec<u64>,
    pub m2: Vec<u64>,
}

impl<'a> ProverEngine<'a> {
    pub fn new(t0: &'a [u64], t1: &'a [u64], t2: &'a [u64], mask_offset: usize, nm: usize) -> Self {
        Self {
            t0,
            t1,
            t2,
            i: mask_offset,
            m0: Vec::with_capacity(nm),
            m1: Vec::with_capacity(nm),
            m2: Vec::with_capacity(nm),
        }
    }
}

impl<'a> Engine for ProverEngine<'a> {
    type V = (u64, u64, u64);
    fn cst(&mut self, c: u64) -> Self::V {
        (c % P, 0, 0)
    }
    fn add(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        (add(a.0, b.0), add(a.1, b.1), add(a.2, b.2))
    }
    fn sub(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        (sub(a.0, b.0), sub(a.1, b.1), sub(a.2, b.2))
    }
    fn add_c(&mut self, a: &Self::V, c: u64) -> Self::V {
        (add(a.0, c), a.1, a.2)
    }
    fn mul_c(&mut self, a: &Self::V, c: u64) -> Self::V {
        (mul(a.0, c), mul(a.1, c), mul(a.2, c))
    }
    fn mul(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        let i = self.i;
        self.i = i + 1;
        let (r0, r1, r2) = (self.t0[i], self.t1[i], self.t2[i]);
        let z0 = sub(
            add(add(mul(a.0, b.0), mul(a.1, b.0)), add(mul(a.0, b.1), r0)),
            r1,
        );
        let z1 = sub(
            add(add(mul(a.1, b.1), mul(a.2, b.1)), add(mul(a.1, b.2), r1)),
            r2,
        );
        let z2 = sub(
            add(add(mul(a.2, b.2), mul(a.0, b.2)), add(mul(a.2, b.0), r2)),
            r0,
        );
        self.m0.push(z0);
        self.m1.push(z1);
        self.m2.push(z2);
        (z0, z1, z2)
    }
}

// Verifier: recomputes party e, consumes party f = e+1's committed
// mult outputs. Lengths are pre-checked by the caller.
pub struct PairEngine<'a> {
    e0: bool,
    f0: bool,
    te: &'a [u64],
    tf: &'a [u64],
    mf: &'a [u64],
    pub i: usize,
    pub j: usize,
    pub me: Vec<u64>,
}

impl<'a> PairEngine<'a> {
    pub fn new(
        e: usize,
        te: &'a [u64],
        tf: &'a [u64],
        mf: &'a [u64],
        mask_offset: usize,
        nm: usize,
    ) -> Self {
        Self {
            e0: e == 0,
            f0: (e + 1).is_multiple_of(3),
            te,
            tf,
            mf,
            i: mask_offset,
            j: 0,
            me: Vec::with_capacity(nm),
        }
    }
}

impl<'a> Engine for PairEngine<'a> {
    type V = (u64, u64);
    fn cst(&mut self, c: u64) -> Self::V {
        (
            if self.e0 { c % P } else { 0 },
            if self.f0 { c % P } else { 0 },
        )
    }
    fn add(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        (add(a.0, b.0), add(a.1, b.1))
    }
    fn sub(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        (sub(a.0, b.0), sub(a.1, b.1))
    }
    fn add_c(&mut self, a: &Self::V, c: u64) -> Self::V {
        (
            if self.e0 { add(a.0, c) } else { a.0 },
            if self.f0 { add(a.1, c) } else { a.1 },
        )
    }
    fn mul_c(&mut self, a: &Self::V, c: u64) -> Self::V {
        (mul(a.0, c), mul(a.1, c))
    }
    fn mul(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        let i = self.i;
        self.i = i + 1;
        let ze = sub(
            add(
                add(mul(a.0, b.0), mul(a.1, b.0)),
                add(mul(a.0, b.1), self.te[i]),
            ),
            self.tf[i],
        );
        let zf = self.mf[self.j];
        self.j += 1;
        self.me.push(ze);
        (ze, zf)
    }
}

fn perm_eng<E: Engine>(eng: &mut E, x: &[E::V; T]) -> [E::V; T] {
    fn m4<E: Engine>(eng: &mut E, x: &mut [E::V; T], k: usize) {
        let (x0, x1, x2, x3) = (
            x[k].clone(),
            x[k + 1].clone(),
            x[k + 2].clone(),
            x[k + 3].clone(),
        );
        let t0 = eng.add(&x0, &x1);
        let t1 = eng.add(&x2, &x3);
        let x1x1 = eng.add(&x1, &x1);
        let t2 = eng.add(&x1x1, &t1);
        let x3x3 = eng.add(&x3, &x3);
        let t3 = eng.add(&x3x3, &t0);
        let t1t1 = eng.add(&t1, &t1);
        let t1t1b = eng.add(&t1, &t1);
        let t1x4 = eng.add(&t1t1, &t1t1b);
        let t4 = eng.add(&t1x4, &t3);
        let t0t0 = eng.add(&t0, &t0);
        let t0t0b = eng.add(&t0, &t0);
        let t0x4 = eng.add(&t0t0, &t0t0b);
        let t5 = eng.add(&t0x4, &t2);
        x[k] = eng.add(&t3, &t5);
        x[k + 1] = t5;
        x[k + 2] = eng.add(&t2, &t4);
        x[k + 3] = t4;
    }

    fn ext<E: Engine>(eng: &mut E, x: &mut [E::V; T]) {
        m4(eng, x, 0);
        m4(eng, x, 4);
        for l in 0..4 {
            let s = eng.add(&x[l], &x[4 + l]);
            x[l] = eng.add(&x[l], &s);
            x[4 + l] = eng.add(&x[4 + l], &s);
        }
    }

    fn sbox<E: Engine>(eng: &mut E, v: &E::V) -> E::V {
        let v2 = eng.mul(v, v);
        let v4 = eng.mul(&v2, &v2);
        let v6 = eng.mul(&v4, &v2);
        eng.mul(&v6, v)
    }

    let mut x = x.clone();
    ext(eng, &mut x);
    for rc in &RC8[0..RF_HALF] {
        for i in 0..T {
            let a = eng.add_c(&x[i], rc[i]);
            x[i] = sbox(eng, &a);
        }
        ext(eng, &mut x);
    }
    for rc in &RC8[RF_HALF..RF_HALF + RP] {
        let a = eng.add_c(&x[0], rc[0]);
        x[0] = sbox(eng, &a);
        let mut s = x[0].clone();
        for xi in &x[1..T] {
            s = eng.add(&s, xi);
        }
        for i in 0..T {
            let m = eng.mul_c(&x[i], MAT_DIAG8_M_1[i]);
            x[i] = eng.add(&m, &s);
        }
    }
    for rc in &RC8[RF_HALF + RP..RF_HALF + RP + RF_HALF] {
        for i in 0..T {
            let a = eng.add_c(&x[i], rc[i]);
            x[i] = sbox(eng, &a);
        }
        ext(eng, &mut x);
    }
    x
}

// wit layout: [s0..s3, bit_0, sib_0[0..3], ..., bit_{d-1}, sib_{d-1}[0..3]]
// outputs: temp_key[0..3], root[0..3], bit_check_0..bit_check_{d-1}
pub fn circuit<E: Engine>(eng: &mut E, ctx: &[u64; 4], depth: usize, wit: &[E::V]) -> Vec<E::V> {
    let zero = eng.cst(0);
    let s = [
        wit[0].clone(),
        wit[1].clone(),
        wit[2].clone(),
        wit[3].clone(),
    ];

    let tag_leaf = eng.cst(TAG_LEAF);
    let st = perm_eng(
        eng,
        &[
            s[0].clone(),
            s[1].clone(),
            s[2].clone(),
            s[3].clone(),
            tag_leaf,
            zero.clone(),
            zero.clone(),
            zero.clone(),
        ],
    );
    let mut cur: Vec<E::V> = st[0..4].to_vec();

    let mut bit_checks = Vec::with_capacity(depth);
    let mut off = 4usize;
    for _ in 0..depth {
        let b = wit[off].clone();
        let sib = &wit[off + 1..off + 5];
        off += 5;
        let mut left = Vec::with_capacity(4);
        let mut right = Vec::with_capacity(4);
        for i in 0..4 {
            let d = eng.sub(&sib[i], &cur[i]);
            let m = eng.mul(&b, &d);
            let li = eng.add(&cur[i], &m); // b ? sib : cur
            let sum = eng.add(&cur[i], &sib[i]);
            right.push(eng.sub(&sum, &li));
            left.push(li);
        }
        let inp: [E::V; T] = [
            left[0].clone(),
            left[1].clone(),
            left[2].clone(),
            left[3].clone(),
            right[0].clone(),
            right[1].clone(),
            right[2].clone(),
            right[3].clone(),
        ];
        let st = perm_eng(eng, &inp);
        cur = (0..4).map(|i| eng.add(&st[i], &inp[i])).collect(); // feed-forward
        let bb = eng.mul(&b, &b);
        bit_checks.push(eng.sub(&bb, &b));
    }

    let tag_key = eng.cst(TAG_KEY);
    let st = perm_eng(
        eng,
        &[
            s[0].clone(),
            s[1].clone(),
            s[2].clone(),
            s[3].clone(),
            tag_key,
            zero.clone(),
            zero.clone(),
            zero,
        ],
    );
    let mut st2: Vec<E::V> = st.to_vec();
    for i in 0..4 {
        st2[i] = eng.add_c(&st2[i], ctx[i]);
    }
    let st3 = perm_eng(
        eng,
        &[
            st2[0].clone(),
            st2[1].clone(),
            st2[2].clone(),
            st2[3].clone(),
            st2[4].clone(),
            st2[5].clone(),
            st2[6].clone(),
            st2[7].clone(),
        ],
    );

    let mut out: Vec<E::V> = st3[0..4].to_vec();
    out.extend(cur);
    out.extend(bit_checks);
    out
}

pub fn num_witness(depth: usize) -> usize {
    4 + 5 * depth
}
pub fn num_outputs(depth: usize) -> usize {
    8 + depth
}
pub fn num_muls(depth: usize) -> usize {
    344 * (3 + depth) + 5 * depth
}
