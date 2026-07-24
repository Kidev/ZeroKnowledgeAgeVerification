// ZKBoo prover / verifier and the AVSM binary wire format, byte
// compatible with code/core.py: proofs interoperate in both directions.

use crate::circuit::{circuit, num_muls, num_outputs, num_witness, PairEngine, ProverEngine};
use crate::field::{add, sub, P};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest as _, Sha3_256, Shake256};

pub const VERSION: &[u8] = b"avsm/1";
pub const MAGIC: &[u8] = b"AVSM";
pub const DEFAULT_REPS: usize = 219; // (2/3)^219 < 2^-128

// Sanity limits for untrusted wire input, matching core.py. A decoder
// that sizes allocations from the header before checking it is a
// memory bomb.
pub const MAX_DEPTH: usize = 64;
pub const MAX_REPS: usize = 4096;

pub struct Repetition {
    pub commits: [[u8; 32]; 3],
    pub outs: [Vec<u64>; 3],
}

pub struct Opening {
    pub seed_e: [u8; 32],
    pub seed_f: [u8; 32],
    pub inputs2: Option<Vec<u64>>,
    pub mults_f: Vec<u64>,
}

pub struct Proof {
    pub depth: usize,
    pub nreps: usize,
    pub reps: Vec<Repetition>,
    pub openings: Vec<Opening>,
}

// SHAKE256 counter mode with rejection sampling, matching
// core.expand_tape byte for byte.
pub fn expand_tape(seed: &[u8], n: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(n + 40);
    let mut ctr: u32 = 0;
    while out.len() < n {
        let need = n - out.len();
        let mut h = Shake256::default();
        h.update(seed);
        h.update(b"|tape|");
        h.update(&ctr.to_le_bytes());
        let mut buf = vec![0u8; (need + 32) * 8];
        h.finalize_xof().read(&mut buf);
        for chunk in buf.chunks_exact(8) {
            let v = u64::from_le_bytes(chunk.try_into().unwrap());
            if v < P {
                out.push(v);
            }
        }
        ctr += 1;
    }
    out.truncate(n);
    out
}

fn u64s_le(vals: &[u64]) -> Vec<u8> {
    let mut b = Vec::with_capacity(vals.len() * 8);
    for v in vals {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

fn commit(seed: &[u8], extra: &[u8], mults: &[u64]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    sha3::Digest::update(&mut h, b"avsm-com/1|");
    sha3::Digest::update(&mut h, seed);
    sha3::Digest::update(&mut h, extra);
    sha3::Digest::update(&mut h, u64s_le(mults));
    h.finalize().into()
}

fn transcript_hash(ctx_bytes: &[u8], reps: &[Repetition]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    sha3::Digest::update(&mut h, b"avsm-fs/1|");
    sha3::Digest::update(&mut h, VERSION);
    sha3::Digest::update(&mut h, ctx_bytes);
    for rep in reps {
        for c in &rep.commits {
            sha3::Digest::update(&mut h, c);
        }
        for outs in &rep.outs {
            sha3::Digest::update(&mut h, u64s_le(outs));
        }
    }
    h.finalize().into()
}

fn challenges(th: &[u8; 32], nreps: usize) -> Vec<u8> {
    let mut trits = Vec::with_capacity(nreps);
    let mut ctr: u32 = 0;
    'outer: loop {
        let mut h = Shake256::default();
        h.update(th);
        h.update(b"|chal|");
        h.update(&ctr.to_le_bytes());
        let mut blk = [0u8; 64];
        h.finalize_xof().read(&mut blk);
        ctr += 1;
        for byte in blk {
            if byte < 255 {
                // unbiased mod 3
                trits.push(byte % 3);
                if trits.len() == nreps {
                    break 'outer;
                }
            }
        }
    }
    trits
}

fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("os rng");
    s
}

struct RepPriv {
    seeds: [[u8; 32]; 3],
    inputs2: Vec<u64>,
    mults: [Vec<u64>; 3],
}

fn prove_one_rep(
    witness: &[u64],
    ctx: &[u64; 4],
    depth: usize,
    nw: usize,
    nm: usize,
    tape_len: usize,
) -> (Repetition, RepPriv) {
    let seeds = [random_seed(), random_seed(), random_seed()];
    let t0 = expand_tape(&seeds[0], tape_len);
    let t1 = expand_tape(&seeds[1], tape_len);
    let t2 = expand_tape(&seeds[2], tape_len);
    // input shares of parties 0 and 1 are their tape prefixes;
    // party 2's shares complete the sharing and are committed explicitly
    let inputs2: Vec<u64> = (0..nw)
        .map(|k| sub(sub(witness[k], t0[k]), t1[k]))
        .collect();
    let shared: Vec<(u64, u64, u64)> = (0..nw).map(|k| (t0[k], t1[k], inputs2[k])).collect();
    let mut eng = ProverEngine::new(&t0, &t1, &t2, nw, nm);
    let outs = circuit(&mut eng, ctx, depth, &shared);
    let outs_by_party = [
        outs.iter().map(|o| o.0).collect::<Vec<u64>>(),
        outs.iter().map(|o| o.1).collect::<Vec<u64>>(),
        outs.iter().map(|o| o.2).collect::<Vec<u64>>(),
    ];
    let commits = [
        commit(&seeds[0], b"", &eng.m0),
        commit(&seeds[1], b"", &eng.m1),
        commit(&seeds[2], &u64s_le(&inputs2), &eng.m2),
    ];
    (
        Repetition {
            commits,
            outs: outs_by_party,
        },
        RepPriv {
            seeds,
            inputs2,
            mults: [eng.m0, eng.m1, eng.m2],
        },
    )
}

pub fn prove(
    witness: &[u64],
    ctx: &[u64; 4],
    depth: usize,
    ctx_bytes: &[u8],
    nreps: usize,
    threads: usize,
) -> Proof {
    let nw = num_witness(depth);
    let nm = num_muls(depth);
    assert_eq!(witness.len(), nw);
    let tape_len = nw + nm;

    let mut results: Vec<Option<(Repetition, RepPriv)>> = (0..nreps).map(|_| None).collect();
    if threads <= 1 {
        for slot in results.iter_mut() {
            *slot = Some(prove_one_rep(witness, ctx, depth, nw, nm, tape_len));
        }
    } else {
        let chunk = nreps.div_ceil(threads);
        std::thread::scope(|s| {
            for chunk_slots in results.chunks_mut(chunk) {
                s.spawn(|| {
                    for slot in chunk_slots.iter_mut() {
                        *slot = Some(prove_one_rep(witness, ctx, depth, nw, nm, tape_len));
                    }
                });
            }
        });
    }
    let (reps, priv_data): (Vec<Repetition>, Vec<RepPriv>) =
        results.into_iter().map(|r| r.unwrap()).unzip();

    let th = transcript_hash(ctx_bytes, &reps);
    let trits = challenges(&th, nreps);

    let openings = trits
        .iter()
        .enumerate()
        .map(|(k, &e)| {
            let e = e as usize;
            let f = (e + 1) % 3;
            let pk = &priv_data[k];
            Opening {
                seed_e: pk.seeds[e],
                seed_f: pk.seeds[f],
                inputs2: if e == 2 || f == 2 {
                    Some(pk.inputs2.clone())
                } else {
                    None
                },
                mults_f: pk.mults[f].clone(),
            }
        })
        .collect();

    Proof {
        depth,
        nreps,
        reps,
        openings,
    }
}

fn verify_one_rep(
    rep: &Repetition,
    op: &Opening,
    e: usize,
    ctx: &[u64; 4],
    depth: usize,
    expected: &[u64],
) -> bool {
    let nw = num_witness(depth);
    let nm = num_muls(depth);
    let nout = num_outputs(depth);
    let tape_len = nw + nm;
    let f = (e + 1) % 3;

    if rep.outs.iter().any(|o| o.len() != nout) {
        return false;
    }
    if rep.outs.iter().any(|o| o.iter().any(|&v| v >= P)) {
        return false;
    }
    for (j, &exp) in expected.iter().enumerate().take(nout) {
        if add(add(rep.outs[0][j], rep.outs[1][j]), rep.outs[2][j]) != exp {
            return false;
        }
    }

    if op.mults_f.len() != nm || op.mults_f.iter().any(|&v| v >= P) {
        return false;
    }
    let tape_e = expand_tape(&op.seed_e, tape_len);
    let tape_f = expand_tape(&op.seed_f, tape_len);

    let inputs2: &[u64] = if e == 2 || f == 2 {
        match &op.inputs2 {
            Some(v) if v.len() == nw && v.iter().all(|&x| x < P) => v,
            _ => return false,
        }
    } else {
        &[]
    };
    let shared: Vec<(u64, u64)> = (0..nw)
        .map(|k| {
            let xe = if e < 2 { tape_e[k] } else { inputs2[k] };
            let xf = if f < 2 { tape_f[k] } else { inputs2[k] };
            (xe, xf)
        })
        .collect();

    let mut eng = PairEngine::new(e, &tape_e, &tape_f, &op.mults_f, nw, nm);
    let pouts = circuit(&mut eng, ctx, depth, &shared);
    if eng.j != nm {
        return false;
    }

    let extra_e = if e == 2 { u64s_le(inputs2) } else { Vec::new() };
    let extra_f = if f == 2 { u64s_le(inputs2) } else { Vec::new() };
    if commit(&op.seed_e, &extra_e, &eng.me) != rep.commits[e] {
        return false;
    }
    if commit(&op.seed_f, &extra_f, &op.mults_f) != rep.commits[f] {
        return false;
    }

    for (j, po) in pouts.iter().enumerate().take(nout) {
        if po.0 != rep.outs[e][j] || po.1 != rep.outs[f][j] {
            return false;
        }
    }
    true
}

pub fn verify(
    proof: &Proof,
    ctx: &[u64; 4],
    depth: usize,
    ctx_bytes: &[u8],
    expected_outputs: &[u64],
    nreps: usize,
    threads: usize,
) -> bool {
    if proof.depth != depth || proof.nreps != nreps {
        return false;
    }
    if proof.reps.len() != nreps || proof.openings.len() != nreps {
        return false;
    }
    let nout = num_outputs(depth);
    if expected_outputs.len() != nout {
        return false;
    }
    let expected: Vec<u64> = expected_outputs.iter().map(|&v| v % P).collect();

    let th = transcript_hash(ctx_bytes, &proof.reps);
    let trits = challenges(&th, nreps);

    let jobs: Vec<usize> = (0..nreps).collect();
    if threads <= 1 {
        jobs.iter().all(|&k| {
            verify_one_rep(
                &proof.reps[k],
                &proof.openings[k],
                trits[k] as usize,
                ctx,
                depth,
                &expected,
            )
        })
    } else {
        let chunk = nreps.div_ceil(threads);
        let mut oks = vec![true; threads.min(nreps)];
        std::thread::scope(|s| {
            for (slot, chunk_jobs) in oks.iter_mut().zip(jobs.chunks(chunk)) {
                let expected = &expected;
                let trits = &trits;
                s.spawn(move || {
                    *slot = chunk_jobs.iter().all(|&k| {
                        verify_one_rep(
                            &proof.reps[k],
                            &proof.openings[k],
                            trits[k] as usize,
                            ctx,
                            depth,
                            expected,
                        )
                    });
                });
            }
        });
        oks.into_iter().all(|b| b)
    }
}

// Binary wire format, identical to core.proof_to_bytes / proof_from_bytes.

pub fn proof_to_bytes(proof: &Proof) -> Vec<u8> {
    let nout = num_outputs(proof.depth);
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(&(proof.depth as u16).to_le_bytes());
    out.extend_from_slice(&(proof.nreps as u32).to_le_bytes());
    for rep in &proof.reps {
        for c in &rep.commits {
            out.extend_from_slice(c);
        }
        for o in &rep.outs {
            assert_eq!(o.len(), nout);
            out.extend_from_slice(&u64s_le(o));
        }
    }
    for op in &proof.openings {
        out.extend_from_slice(&op.seed_e);
        out.extend_from_slice(&op.seed_f);
        match &op.inputs2 {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&u64s_le(v));
            }
            None => out.push(0),
        }
        out.extend_from_slice(&u64s_le(&op.mults_f));
    }
    out
}

fn read_u64s(data: &[u8], off: &mut usize, n: usize) -> Option<Vec<u64>> {
    let need = n * 8;
    if *off + need > data.len() {
        return None;
    }
    let v = data[*off..*off + need]
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    *off += need;
    Some(v)
}

pub fn proof_from_bytes(data: &[u8]) -> Option<Proof> {
    let mut off = 0usize;
    if data.len() < 4 + VERSION.len() + 6 || &data[..4] != MAGIC {
        return None;
    }
    off += 4;
    if &data[off..off + VERSION.len()] != VERSION {
        return None;
    }
    off += VERSION.len();
    let depth = u16::from_le_bytes(data[off..off + 2].try_into().ok()?) as usize;
    let nreps = u32::from_le_bytes(data[off + 2..off + 6].try_into().ok()?) as usize;
    off += 6;
    if !(1..=MAX_DEPTH).contains(&depth) || !(1..=MAX_REPS).contains(&nreps) {
        return None;
    }
    let nout = num_outputs(depth);
    let nw = num_witness(depth);
    let nm = num_muls(depth);

    // Reject on declared size before allocating anything from it. The
    // spread between lo and hi is the optional inputs2 block, present
    // only in the two openings out of three that touch party 2.
    let body = data.len().checked_sub(off)?;
    let lo = nreps.checked_mul(96 + 3 * 8 * nout + 64 + 1 + 8 * nm)?;
    let hi = lo.checked_add(nreps.checked_mul(8 * nw)?)?;
    if body < lo || body > hi {
        return None;
    }

    let mut reps = Vec::with_capacity(nreps);
    for _ in 0..nreps {
        if off + 96 > data.len() {
            return None;
        }
        let mut commits = [[0u8; 32]; 3];
        for c in commits.iter_mut() {
            c.copy_from_slice(&data[off..off + 32]);
            off += 32;
        }
        let o0 = read_u64s(data, &mut off, nout)?;
        let o1 = read_u64s(data, &mut off, nout)?;
        let o2 = read_u64s(data, &mut off, nout)?;
        reps.push(Repetition {
            commits,
            outs: [o0, o1, o2],
        });
    }
    let mut openings = Vec::with_capacity(nreps);
    for _ in 0..nreps {
        if off + 65 > data.len() {
            return None;
        }
        let mut seed_e = [0u8; 32];
        seed_e.copy_from_slice(&data[off..off + 32]);
        let mut seed_f = [0u8; 32];
        seed_f.copy_from_slice(&data[off + 32..off + 64]);
        off += 64;
        let has2 = match data[off] {
            0 => false,
            1 => true,
            _ => return None,
        };
        off += 1;
        let inputs2 = if has2 {
            Some(read_u64s(data, &mut off, nw)?)
        } else {
            None
        };
        let mults_f = read_u64s(data, &mut off, nm)?;
        openings.push(Opening {
            seed_e,
            seed_f,
            inputs2,
            mults_f,
        });
    }
    if off != data.len() {
        return None;
    }
    Some(Proof {
        depth,
        nreps,
        reps,
        openings,
    })
}
