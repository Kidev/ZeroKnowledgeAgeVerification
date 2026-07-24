"""
rust_interop.py - cross-implementation check with the Rust PoC.

Both implementations share the wire format and the Fiat-Shamir
transcript, so proofs interoperate in both directions:

  emit <dir> [depth] [nreps]   prove here, for rust: avsm-poc verify <dir>
  check <dir>                  verify a <dir>/proof.bin + public.txt pair
                               produced by either implementation

Full loop from the repository root:

  cd code/rust && cargo run --release -- prove /tmp/rust-out
  cd code/python && python3 rust_interop.py check /tmp/rust-out
  python3 rust_interop.py emit /tmp/py-out 32 219
  cd code/rust && cargo run --release -- verify /tmp/py-out
"""

import os
import secrets
import sys
import time

import core
import protocol


def _write_public(dirpath, domain, epoch, nonce, depth, nreps, root, tk):
    with open(os.path.join(dirpath, "public.txt"), "w") as fh:
        fh.write(f"domain={domain}\n")
        fh.write(f"epoch={epoch}\n")
        fh.write(f"nonce={nonce.hex()}\n")
        fh.write(f"depth={depth}\n")
        fh.write(f"nreps={nreps}\n")
        fh.write("root=" + ",".join(map(str, root)) + "\n")
        fh.write("temp_key=" + ",".join(map(str, tk)) + "\n")


def _read_public(dirpath):
    pub = {}
    with open(os.path.join(dirpath, "public.txt")) as fh:
        for line in fh:
            k, v = line.strip().split("=", 1)
            pub[k] = v
    return (pub["domain"], int(pub["epoch"]), bytes.fromhex(pub["nonce"]),
            int(pub["depth"]), int(pub["nreps"]),
            tuple(int(x) for x in pub["root"].split(",")),
            tuple(int(x) for x in pub["temp_key"].split(",")))


def emit(dirpath, depth=32, nreps=core.DEFAULT_REPS):
    tree = core.SparseMerkleTree(depth)
    secret = core.rand_digest()
    idx = tree.append(core.leaf_hash_native(secret))
    tree.append(core.leaf_hash_native(core.rand_digest()))
    root = tree.root()
    bits, sibs = tree.path(idx)
    domain, epoch = "interop.example", 100
    nonce = secrets.token_bytes(16)
    ctx = core.context_digest(domain, epoch)
    tk = core.prf_native(secret, ctx)
    wit = list(secret)
    for i in range(depth):
        wit.append(bits[i])
        wit.extend(sibs[i])
    ctx_bytes = protocol.token_context_bytes(domain, epoch, root, tk, nonce)
    t0 = time.time()
    proof = core.prove(wit, ctx, depth, ctx_bytes, nreps)
    blob = core.proof_to_bytes(proof)
    print(f"python proved in {time.time() - t0:.1f}s, "
          f"proof {len(blob) / 1e6:.1f} MB")
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, "proof.bin"), "wb") as fh:
        fh.write(blob)
    _write_public(dirpath, domain, epoch, nonce, depth, nreps, root, tk)
    print(f"wrote {dirpath}/proof.bin and {dirpath}/public.txt")


def check(dirpath):
    domain, epoch, nonce, depth, nreps, root, tk = _read_public(dirpath)
    with open(os.path.join(dirpath, "proof.bin"), "rb") as fh:
        proof = core.proof_from_bytes(fh.read())
    ctx = core.context_digest(domain, epoch)
    ctx_bytes = protocol.token_context_bytes(domain, epoch, root, tk, nonce)
    expected = list(tk) + list(root) + [0] * depth
    t0 = time.time()
    ok = core.verify(proof, ctx, depth, ctx_bytes, expected, nreps)
    print(f"python verified in {time.time() - t0:.1f}s: "
          + ("OK" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "emit":
        emit(sys.argv[2],
             int(sys.argv[3]) if len(sys.argv) > 3 else 32,
             int(sys.argv[4]) if len(sys.argv) > 4 else core.DEFAULT_REPS)
    elif len(sys.argv) >= 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
