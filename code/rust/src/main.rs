// avsm-poc: native Rust proof of concept for the avsm protocol.
// Same field, permutation, circuit, Fiat-Shamir transcript, and binary
// wire format as the Python reference in code/python/, so proofs
// interoperate in both directions. See the repository README.
//
// Subcommands:
//   selftest                     KATs against the Python reference plus
//                                end-to-end prove/verify and tampering checks
//   bench [d] [tau] [threads]    time prove and verify (default 32 219 1)
//   prove <dir> [d] [tau] [thr]  full wallet flow, writes proof.bin and
//                                public.txt for cross-checking with Python
//   verify <dir> [threads]       verify a proof.bin + public.txt pair,
//                                whichever implementation produced it

mod circuit;
mod constants;
mod field;
mod poseidon2;
mod zkboo;

use circuit::{circuit as run_circuit, num_muls, NativeEngine};
use field::P;
use poseidon2::{
    context_digest, leaf_hash_native, prf_native, ser_digest, Digest, SparseMerkleTree,
};
use std::time::Instant;
use zkboo::{expand_tape, proof_from_bytes, proof_to_bytes, prove, verify, DEFAULT_REPS};

const DEFAULT_DEPTH: usize = 32;

fn rand_field() -> u64 {
    loop {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("os rng");
        let v = u64::from_le_bytes(b);
        if v < P {
            return v;
        }
    }
}

fn rand_digest() -> Digest {
    [rand_field(), rand_field(), rand_field(), rand_field()]
}

// Matches protocol.token_context_bytes. Injectivity of this encoding is
// what Theorem 4 (replay) and Proposition 1 (threshold isolation) rest
// on: every field after the domain has a fixed width, so it is enough
// that the domain field carry no separator. Enforced, not assumed.
fn token_context_bytes(
    domain: &str,
    epoch: u64,
    root: &Digest,
    temp_key: &Digest,
    nonce: &[u8],
) -> Vec<u8> {
    assert!(
        !domain.is_empty() && !domain.contains('|'),
        "domain field must be non-empty and free of the separator"
    );
    assert_eq!(nonce.len(), 16, "nonce must be 16 bytes");
    let mut b = Vec::new();
    b.extend_from_slice(b"avsm-token/1|");
    b.extend_from_slice(domain.as_bytes());
    b.extend_from_slice(b"|");
    b.extend_from_slice(&epoch.to_le_bytes());
    b.extend_from_slice(b"|");
    b.extend_from_slice(&ser_digest(root));
    b.extend_from_slice(b"|");
    b.extend_from_slice(&ser_digest(temp_key));
    b.extend_from_slice(b"|");
    b.extend_from_slice(nonce);
    b
}

fn build_witness(secret: &Digest, bits: &[u64], sibs: &[Digest]) -> Vec<u64> {
    let mut wit = secret.to_vec();
    for (b, sib) in bits.iter().zip(sibs) {
        wit.push(*b);
        wit.extend_from_slice(sib);
    }
    wit
}

fn expected_outputs(temp_key: &Digest, root: &Digest, depth: usize) -> Vec<u64> {
    let mut e = temp_key.to_vec();
    e.extend_from_slice(root);
    e.extend(std::iter::repeat_n(0, depth));
    e
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn selftest() {
    // KATs generated with the Python reference (code/python/core.py)
    assert_eq!(
        leaf_hash_native(&[1, 2, 3, 4]),
        [
            6342895394156475262,
            1577107449524149288,
            7840524846651105492,
            18417668153615065365
        ]
    );
    assert_eq!(
        poseidon2::compress_native(&[1, 2, 3, 4], &[5, 6, 7, 8]),
        [
            10577501287789148138,
            5800891928410257857,
            3854182729755511196,
            4756945600777909255
        ]
    );
    assert_eq!(
        prf_native(&[1, 2, 3, 4], &[9, 10, 11, 12]),
        [
            653001002771353145,
            1525173288558247566,
            16844415803975026024,
            17239186809802413000
        ]
    );
    assert_eq!(
        context_digest("example.com", 5),
        [
            16440778878863688502,
            9697489064336942563,
            3589708795201654670,
            11032652862285394682
        ]
    );
    assert_eq!(
        poseidon2::empty_leaf(),
        [
            4303809905960637013,
            10632898477035230791,
            4685855492600479895,
            11603576993829804265
        ]
    );
    assert_eq!(
        &expand_tape(&[0x42u8; 32], 4)[..],
        &[
            1471157187303006640,
            4841160878767844317,
            3895878302384988299,
            13260758840160989358
        ]
    );
    println!("ok  known-answer tests against the Python reference");

    // end to end at reduced parameters
    let depth = 6usize;
    let nreps = 8usize;
    let mut tree = SparseMerkleTree::new(depth);
    let secret = rand_digest();
    let idx = tree.append(leaf_hash_native(&secret));
    tree.append(leaf_hash_native(&rand_digest()));
    let root = tree.root();
    let (bits, sibs) = tree.path(idx);
    let ctx = context_digest("selftest.example", 7);
    let temp_key = prf_native(&secret, &ctx);
    let wit = build_witness(&secret, &bits, &sibs);

    let mut nat = NativeEngine;
    let shares_check = run_circuit(&mut nat, &ctx, depth, &wit);
    let expected = expected_outputs(&temp_key, &root, depth);
    assert_eq!(shares_check, expected);
    println!("ok  native circuit evaluation matches expected outputs");

    let ctx_bytes =
        token_context_bytes("selftest.example", 7, &root, &temp_key, b"nonce-0123456789");
    let proof = prove(&wit, &ctx, depth, &ctx_bytes, nreps, 1);
    assert!(verify(&proof, &ctx, depth, &ctx_bytes, &expected, nreps, 1));
    assert!(!verify(
        &proof,
        &ctx,
        depth,
        b"other ctx",
        &expected,
        nreps,
        1
    ));
    let mut bad = expected.clone();
    bad[0] = bad[0].wrapping_add(1) % P;
    assert!(!verify(&proof, &ctx, depth, &ctx_bytes, &bad, nreps, 1));
    println!("ok  prove/verify roundtrip, transcript and output binding");

    let blob = proof_to_bytes(&proof);
    let p2 = proof_from_bytes(&blob).expect("decode");
    assert!(verify(&p2, &ctx, depth, &ctx_bytes, &expected, nreps, 1));
    let mut tampered = blob.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    if let Some(p3) = proof_from_bytes(&tampered) {
        assert!(!verify(&p3, &ctx, depth, &ctx_bytes, &expected, nreps, 1))
    }
    println!("ok  wire roundtrip, bit flip rejected");

    // hostile headers must be refused before anything is sized from them
    let mut hdr = Vec::new();
    hdr.extend_from_slice(zkboo::MAGIC);
    hdr.extend_from_slice(zkboo::VERSION);
    for (d, r) in [(32u16, 0xFFFF_FFFFu32), (0xFFFF, 1), (32, 0)] {
        let mut bomb = hdr.clone();
        bomb.extend_from_slice(&d.to_le_bytes());
        bomb.extend_from_slice(&r.to_le_bytes());
        assert!(proof_from_bytes(&bomb).is_none());
    }
    assert!(proof_from_bytes(&[]).is_none());
    assert!(proof_from_bytes(&hdr).is_none());
    println!("ok  wire decoder rejects hostile headers without allocating");
    println!("\nall selftests passed");
}

fn bench(depth: usize, nreps: usize, threads: usize) {
    let mut tree = SparseMerkleTree::new(depth);
    let secret = rand_digest();
    let idx = tree.append(leaf_hash_native(&secret));
    tree.append(leaf_hash_native(&rand_digest()));
    tree.append(leaf_hash_native(&rand_digest()));
    let root = tree.root();
    let (bits, sibs) = tree.path(idx);
    let ctx = context_digest("bench.example", 42);
    let temp_key = prf_native(&secret, &ctx);
    let wit = build_witness(&secret, &bits, &sibs);
    let expected = expected_outputs(&temp_key, &root, depth);
    let ctx_bytes = token_context_bytes("bench.example", 42, &root, &temp_key, b"bench-nonce-0000");

    let t0 = Instant::now();
    let proof = prove(&wit, &ctx, depth, &ctx_bytes, nreps, threads);
    let t_prove = t0.elapsed();
    let blob = proof_to_bytes(&proof);
    let t1 = Instant::now();
    let ok = verify(&proof, &ctx, depth, &ctx_bytes, &expected, nreps, threads);
    let t_verify = t1.elapsed();
    assert!(ok);
    println!(
        "depth={} tau={} threads={} muls/rep={}",
        depth,
        nreps,
        threads,
        num_muls(depth)
    );
    println!("prove  {:>8.1} ms", t_prove.as_secs_f64() * 1e3);
    println!("verify {:>8.1} ms", t_verify.as_secs_f64() * 1e3);
    println!("proof  {:>8.2} MB", blob.len() as f64 / 1e6);
}

fn prove_cmd(dir: &str, depth: usize, nreps: usize, threads: usize) {
    let mut tree = SparseMerkleTree::new(depth);
    let secret = rand_digest();
    let idx = tree.append(leaf_hash_native(&secret));
    tree.append(leaf_hash_native(&rand_digest()));
    let root = tree.root();
    let (bits, sibs) = tree.path(idx);

    let domain = "interop.example";
    let epoch = 100u64;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("os rng");

    let ctx = context_digest(domain, epoch);
    let temp_key = prf_native(&secret, &ctx);
    let wit = build_witness(&secret, &bits, &sibs);
    let ctx_bytes = token_context_bytes(domain, epoch, &root, &temp_key, &nonce);

    let t0 = Instant::now();
    let proof = prove(&wit, &ctx, depth, &ctx_bytes, nreps, threads);
    println!("proved in {:.1} ms", t0.elapsed().as_secs_f64() * 1e3);

    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(format!("{}/proof.bin", dir), proof_to_bytes(&proof)).expect("write proof");
    let pub_txt = format!(
        "domain={}\nepoch={}\nnonce={}\ndepth={}\nnreps={}\nroot={}\ntemp_key={}\n",
        domain,
        epoch,
        hex(&nonce),
        depth,
        nreps,
        root.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(","),
        temp_key
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    std::fs::write(format!("{}/public.txt", dir), pub_txt).expect("write public");
    println!("wrote {}/proof.bin and {}/public.txt", dir, dir);
}

fn parse_digest(s: &str) -> Digest {
    let v: Vec<u64> = s
        .split(',')
        .map(|x| x.trim().parse().expect("u64"))
        .collect();
    [v[0], v[1], v[2], v[3]]
}

fn verify_cmd(dir: &str, threads: usize) {
    let pub_txt = std::fs::read_to_string(format!("{}/public.txt", dir)).expect("read public.txt");
    let mut domain = String::new();
    let mut epoch = 0u64;
    let mut nonce = Vec::new();
    let mut depth = 0usize;
    let mut nreps = 0usize;
    let mut root = [0u64; 4];
    let mut temp_key = [0u64; 4];
    for line in pub_txt.lines() {
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k {
            "domain" => domain = v.to_string(),
            "epoch" => epoch = v.parse().expect("epoch"),
            "nonce" => nonce = unhex(v),
            "depth" => depth = v.parse().expect("depth"),
            "nreps" => nreps = v.parse().expect("nreps"),
            "root" => root = parse_digest(v),
            "temp_key" => temp_key = parse_digest(v),
            _ => {}
        }
    }
    let blob = std::fs::read(format!("{}/proof.bin", dir)).expect("read proof.bin");
    let proof = match proof_from_bytes(&blob) {
        Some(p) => p,
        None => {
            println!("verify: FAIL (malformed proof)");
            std::process::exit(1);
        }
    };
    let ctx = context_digest(&domain, epoch);
    let expected = expected_outputs(&temp_key, &root, depth);
    let ctx_bytes = token_context_bytes(&domain, epoch, &root, &temp_key, &nonce);
    let t0 = Instant::now();
    let ok = verify(&proof, &ctx, depth, &ctx_bytes, &expected, nreps, threads);
    println!(
        "verified in {:.1} ms: {}",
        t0.elapsed().as_secs_f64() * 1e3,
        if ok { "OK" } else { "FAIL" }
    );
    if !ok {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("selftest");
    let num = |i: usize, d: usize| args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    match cmd {
        "selftest" => selftest(),
        "bench" => bench(num(2, DEFAULT_DEPTH), num(3, DEFAULT_REPS), num(4, 1)),
        "prove" => {
            let dir = args
                .get(2)
                .expect("prove <dir> [depth] [reps] [threads]")
                .clone();
            prove_cmd(&dir, num(3, DEFAULT_DEPTH), num(4, DEFAULT_REPS), num(5, 1));
        }
        "verify" => {
            let dir = args.get(2).expect("verify <dir> [threads]").clone();
            verify_cmd(&dir, num(3, 1));
        }
        _ => {
            eprintln!(
                "usage: avsm-poc [selftest | bench [d] [tau] [threads] | \
                       prove <dir> [d] [tau] [threads] | verify <dir> [threads]]"
            );
            std::process::exit(2);
        }
    }
}
