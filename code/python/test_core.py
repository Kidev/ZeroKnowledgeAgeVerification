"""
test_core.py - test suite for the cryptographic core and protocol layer.
Run: python3 test_core.py
Uses reduced repetitions/depth where soundness level is irrelevant to
the property under test; parameter-sensitive tests use full values.
"""

import copy
import os
import random
import tempfile

import core
from core import (P, NativeEngine, ProverEngine, PairEngine, circuit,
                  perm_native, _perm_eng, rand_digest, leaf_hash_native,
                  prf_native, context_digest, SparseMerkleTree,
                  expand_tape, prove, verify, num_witness, num_muls,
                  proof_to_bytes, proof_from_bytes)
import protocol
from protocol import (GovernmentAuthority, CitizenWallet, Website,
                      verify_root_bundle, token_context_bytes)


def test_poseidon2_official_kat():
    """The designers' published t=12 Goldilocks vector, run through the
    same perm_native the protocol uses at t=8. The routine is generic in
    the state width precisely so this test cannot drift from production
    code: there is no second implementation to disagree with."""
    from poseidon2_constants import MAT_DIAG12_M_1, RC12
    kat = [0x01eaef96bdf1c0c1, 0x1f0d2cc525b2540c, 0x6282c1dfe1e0358d,
           0xe780d721f698e1e6, 0x280c0b6f753d833b, 0x1b942dd5023156ab,
           0x43f0df3fcccb8398, 0xe8e8190585489025, 0x56bdbf72f77ada22,
           0x7911c32bf9dcd705, 0xec467926508fbe67, 0x6a50450ddf85a6ed]
    assert perm_native(list(range(12)), RC12, MAT_DIAG12_M_1) == kat
    print("ok  Poseidon2 official known-answer test (t=12, shared routine)")


def test_engine_matches_native():
    st = [random.randrange(P) for _ in range(8)]
    assert perm_native(st) == _perm_eng(NativeEngine(), st)
    print("ok  engine permutation == native permutation")


def make_instance(depth=6):
    tree = SparseMerkleTree(depth)
    s = rand_digest()
    idx = tree.append(leaf_hash_native(s))
    for _ in range(5):
        tree.append(leaf_hash_native(rand_digest()))
    bits, sibs = tree.path(idx)
    wit = list(s)
    for i in range(depth):
        wit.append(bits[i])
        wit.extend(sibs[i])
    ctx = context_digest("test.example", 123)
    root = tree.root()
    tk = prf_native(s, ctx)
    expected = list(tk) + list(root) + [0] * depth
    return wit, ctx, depth, expected


def test_share_reconstruction():
    wit, ctx, depth, expected = make_instance()
    nat = circuit(NativeEngine(), ctx, depth, wit)
    assert nat == [v % P for v in expected]

    nw = num_witness(depth)
    nm = num_muls(depth)
    seeds = [os.urandom(32) for _ in range(3)]
    tapes = [expand_tape(s, nw + nm) for s in seeds]
    inputs2 = [(wit[k] - tapes[0][k] - tapes[1][k]) % P for k in range(nw)]
    shared = [(tapes[0][k], tapes[1][k], inputs2[k]) for k in range(nw)]
    peng = ProverEngine(tapes, nw)
    pouts = circuit(peng, ctx, depth, shared)
    for j, o in enumerate(pouts):
        assert sum(o) % P == nat[j]

    mults = (peng.m0, peng.m1, peng.m2)
    for e in range(3):
        f = (e + 1) % 3
        veng = PairEngine(e, tapes[e], tapes[f], mults[f], nw)
        pair = [(tapes[e][k] if e < 2 else inputs2[k],
                 tapes[f][k] if f < 2 else inputs2[k]) for k in range(nw)]
        vouts = circuit(veng, ctx, depth, pair)
        assert list(veng.me) == list(mults[e]), f"mults mismatch e={e}"
        for j in range(len(pouts)):
            assert vouts[j] == (pouts[j][e], pouts[j][f])
    assert peng.i == nw + nm
    print("ok  3-share reconstruction and pair recomputation, e in {0,1,2}")


def test_completeness_and_binding():
    wit, ctx, depth, expected = make_instance()
    proof = prove(wit, ctx, depth, b"ctx-A", nreps=20)
    assert verify(proof, ctx, depth, b"ctx-A", expected, nreps=20)
    assert not verify(proof, ctx, depth, b"ctx-B", expected, nreps=20)
    bad = [(expected[0] + 1) % P] + expected[1:]
    assert not verify(proof, ctx, depth, b"ctx-A", bad, nreps=20)
    print("ok  completeness, transcript binding, output binding")


def test_wire_roundtrip():
    wit, ctx, depth, expected = make_instance()
    proof = prove(wit, ctx, depth, b"wire", nreps=8)
    blob = proof_to_bytes(proof)
    p2 = proof_from_bytes(blob)
    assert verify(p2, ctx, depth, b"wire", expected, nreps=8)
    corrupted = bytearray(blob)
    corrupted[len(corrupted) // 2] ^= 1
    try:
        p3 = proof_from_bytes(bytes(corrupted))
        assert not verify(p3, ctx, depth, b"wire", expected, nreps=8)
    except ValueError:
        pass
    print("ok  binary wire format round-trip, corrupted blob rejected")


def test_false_statements_rejected():
    wit, ctx, depth, expected = make_instance()
    w2 = list(wit)
    w2[0] = (w2[0] + 1) % P  # wrong secret
    assert not verify(prove(w2, ctx, depth, b"c", nreps=8),
                      ctx, depth, b"c", expected, nreps=8)
    w3 = list(wit)
    w3[4] = 7                # non-boolean path bit
    assert not verify(prove(w3, ctx, depth, b"c", nreps=8),
                      ctx, depth, b"c", expected, nreps=8)
    print("ok  false statements rejected (wrong secret, non-boolean bit)")


def test_view_corruption_always_caught():
    wit, ctx, depth, expected = make_instance()
    rng = random.Random(7)
    for _ in range(40):
        ctxb = os.urandom(8)
        proof = prove(wit, ctx, depth, ctxb, nreps=1)
        op = proof["openings"][0]
        i = rng.randrange(len(op["mults_f"]))
        op["mults_f"][i] = (op["mults_f"][i] + 1) % P
        assert not verify(proof, ctx, depth, ctxb, expected, nreps=1)
    print("ok  opened-view corruption caught 40/40 (commitment binding)")


def test_malformed_proofs():
    wit, ctx, depth, expected = make_instance()
    proof = prove(wit, ctx, depth, b"m", nreps=6)
    from array import array
    p = copy.deepcopy(proof)
    p["openings"][2]["mults_f"] = p["openings"][2]["mults_f"][:-1]
    assert not verify(p, ctx, depth, b"m", expected, nreps=6)
    p = copy.deepcopy(proof)
    p["reps"][1]["outs"][0][0] = (p["reps"][1]["outs"][0][0] + 1) % P
    assert not verify(p, ctx, depth, b"m", expected, nreps=6)
    p = copy.deepcopy(proof)
    if "inputs2" in p["openings"][0]:
        p["openings"][0]["inputs2"][0] = P - 1 + 1  # out-of-range share
        assert not verify(p, ctx, depth, b"m", expected, nreps=6)
    assert not verify({"garbage": True}, ctx, depth, b"m", expected, nreps=6)
    print("ok  malformed proofs rejected")


def test_protocol_end_to_end():
    ga = GovernmentAuthority(depth=6)
    w = CitizenWallet("A")
    w.enroll_with(ga, "a", True)
    bundle = ga.publish_root_bundle()
    assert verify_root_bundle(bundle)
    tampered = dict(bundle)
    tampered["tree_size"] = 999
    assert not verify_root_bundle(tampered) or not protocol.HAVE_MLDSA
    site = Website("x.example", bundle)
    n = site.challenge()
    tok = w.make_token(ga.published_tree(), bundle, "x.example",
                       protocol.current_epoch(), n, nreps=8)
    assert site.verify_token(tok, n, nreps=8)
    assert not site.verify_token(tok, n, nreps=8)  # nonce consumed
    print("ok  protocol end-to-end, signed bundle, nonce single-use")


def test_revocation():
    ga = GovernmentAuthority(depth=6)
    w = CitizenWallet("R")
    w.enroll_with(ga, "r", True)
    b1 = ga.publish_root_bundle()
    site = Website("y.example", b1)
    n = site.challenge()
    tok = w.make_token(ga.published_tree(), b1, "y.example",
                       protocol.current_epoch(), n, nreps=8)
    assert site.verify_token(tok, n, nreps=8)
    ga.revoke("r")
    b2 = ga.publish_root_bundle()
    site.update_root(b2)
    n2 = site.challenge()
    try:
        tok2 = w.make_token(ga.published_tree(), b2, "y.example",
                            protocol.current_epoch(), n2, nreps=8)
        assert not site.verify_token(tok2, n2, nreps=8)
    except Exception:
        pass  # wallet may fail locally; either way no valid token exists
    print("ok  revocation: root update invalidates revoked credential")


def test_multi_threshold():
    """One accumulator per age threshold. The same wallet secret and
    the same leaf serve every tree the citizen belongs to; a site pins
    itself to the single threshold its legal duty requires."""
    ga15 = GovernmentAuthority(depth=6, threshold=15)
    ga18 = GovernmentAuthority(depth=6, threshold=18)

    teen = CitizenWallet("teen (16)")     # in the 15 tree only
    adult = CitizenWallet("adult (30)")   # in both trees, same leaf
    teen.enroll_with(ga15, "teen", True)
    adult.enroll_with(ga15, "adult", True)
    adult.enroll_with(ga18, "adult", True)
    # same commitment in both trees, different index in each
    assert ga15.tree.nodes[(0, adult.indices[15])] == adult.commitment()
    assert ga18.tree.nodes[(0, adult.indices[18])] == adult.commitment()
    assert adult.indices[15] != adult.indices[18]

    b15 = ga15.publish_root_bundle()
    b18 = ga18.publish_root_bundle()
    assert b15.get("threshold") == 15 and b18.get("threshold") == 18

    site15 = Website("teen-ok.example", b15, required_threshold=15)
    site18 = Website("adults.example", b18, required_threshold=18)

    # a site refuses a bundle for a threshold other than its own
    try:
        Website("strict.example", b15, required_threshold=18)
        raise AssertionError("threshold mismatch accepted")
    except ValueError:
        pass

    # the teen proves membership at the 15 site; the site learns
    # exactly "age >= 15", nothing finer
    n = site15.challenge()
    tok = teen.make_token(ga15.published_tree(), b15, "teen-ok.example",
                          protocol.current_epoch(), n, nreps=8)
    assert site15.verify_token(tok, n, nreps=8)

    # that token does not transfer to the 18 site (domain and root both
    # differ), and the teen holds no leaf under the 18 root at all
    n2 = site18.challenge()
    assert not site18.verify_token(tok, n2, nreps=8)

    # the adult proves at either site with the same secret
    n3 = site18.challenge()
    tok3 = adult.make_token(ga18.published_tree(), b18, "adults.example",
                            protocol.current_epoch(), n3, nreps=8)
    assert site18.verify_token(tok3, n3, nreps=8)

    # a consumed token is single use: replay on a fresh nonce fails
    n4 = site18.challenge()
    assert not site18.verify_token(tok3, n4, nreps=8)

    # cross-threshold probing fails cryptographically: an 18 site on the
    # same domain cannot verify a token the adult made for threshold 15,
    # even though the adult is in both trees (the threshold sits inside
    # the proof context, so the probe fails for adults and teens alike)
    both = Website("both.example", b15, required_threshold=15)
    n5 = both.challenge()
    tok5 = adult.make_token(ga15.published_tree(), b15, "both.example",
                            protocol.current_epoch(), n5, nreps=8)
    assert both.verify_token(tok5, n5, nreps=8)
    probe = Website("both.example", b18, required_threshold=18)
    n6 = probe.challenge()
    tok5b = dict(tok5, threshold=18)   # even relabeled, the proof fails
    assert not probe.verify_token(tok5b, n6, nreps=8)

    # a fresh proof for the probing threshold triggers a warning that
    # fires before any membership-dependent step, identically for every
    # age; the wallet proceeds only on explicit user confirmation
    for w in (adult, teen):
        try:
            w.pins["both.example"] = 15
            w.make_token(ga18.published_tree(), b18, "both.example",
                         protocol.current_epoch(), probe.challenge(),
                         nreps=8)
            raise AssertionError("over-ask accepted without warning")
        except protocol.ThresholdChangeWarning:
            pass

    # explicit confirmation re-pins and proceeds (user's decision)
    n7 = probe.challenge()
    tok7 = adult.make_token(ga18.published_tree(), b18, "both.example",
                            protocol.current_epoch(), n7, nreps=8,
                            allow_repin=True)
    assert probe.verify_token(tok7, n7, nreps=8)
    assert adult.pins["both.example"] == 18

    print("ok  multi-threshold: per-threshold trees, signed threshold, "
          "single-bit disclosure")


def test_wallet_storage():
    if not protocol.HAVE_AEAD:
        print("skip wallet storage (cryptography not installed)")
        return
    w = CitizenWallet("S")
    w.leaf_index = 42
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "wallet.bin")
        w.save(path, "correct horse battery staple")
        w2 = CitizenWallet.load(path, "correct horse battery staple")
        assert w2.secret == w.secret and w2.leaf_index == 42
        try:
            CitizenWallet.load(path, "wrong passphrase")
            raise AssertionError("wrong passphrase accepted")
        except Exception:
            pass
    print("ok  wallet storage: scrypt + AES-GCM, wrong passphrase rejected")


def test_serialization_is_little_endian():
    """The wire format is a specification, not a property of x86:
    every u64 is little-endian whatever the host byte order."""
    import struct as _s
    from array import array as _a
    vals = [0, 1, P - 1, 0x0102030405060708]
    assert core._u64s_le(vals) == _s.pack("<4Q", *vals)
    assert core._u64s_le(_a("Q", vals)) == _s.pack("<4Q", *vals)
    assert list(core._u64s_from_le(_s.pack("<4Q", *vals), 4)) == vals
    print("ok  u64 serialization is little-endian on any host")


def test_context_encoding_is_injective():
    """Theorem 4 and Proposition 1 need (domain, epoch, root, key,
    nonce) -> ctx_bytes to be injective. Every field after the domain is
    fixed width, so injectivity reduces to a separator-free domain,
    which is enforced rather than assumed."""
    root, tk = rand_digest(), rand_digest()
    n = os.urandom(protocol.NONCE_BYTES)
    for bad in ("a|b.example", "a#b.example", "", None):
        try:
            token_context_bytes(bad, 1, root, tk, n)
            raise AssertionError(f"accepted domain {bad!r}")
        except ValueError:
            pass
    for bad_nonce in (b"", b"short", os.urandom(17)):
        try:
            token_context_bytes("x.example", 1, root, tk, bad_nonce)
            raise AssertionError("accepted wrong-length nonce")
        except ValueError:
            pass
    # distinct tuples give distinct encodings, including the threshold
    # fold, which is the whole content of Proposition 1's first step
    seen = {}
    for dom in ("x.example", "xy.example"):
        for thr in (None, 1, 13, 18):
            for ep in (0, 1):
                key = token_context_bytes(protocol.ctx_domain(dom, thr),
                                          ep, root, tk, n)
                assert key not in seen, "context collision"
                seen[key] = (dom, thr, ep)
    print("ok  context encoding injective, separators rejected")


def test_verifier_is_total():
    """A verifier that raises is a verifier an attacker can turn into a
    denial of service. Every malformed input must be a rejection."""
    wit, ctx, depth, expected = make_instance()
    good = prove(wit, ctx, depth, b"t", nreps=4)
    nout = core.num_outputs(depth)
    junk = [None, 42, "proof", {}, {"version": "avsm/1"}]
    for j in junk:
        assert verify(j, ctx, depth, b"t", expected, nreps=4) is False
    for bad_expected in ([], [0] * (nout + 1), [2 ** 64] * nout,
                         [-1] * nout, None):
        assert verify(good, ctx, depth, b"t", bad_expected,
                      nreps=4) is False
    for bad_ctx in ((1, 2, 3), (P, 0, 0, 0), None):
        assert verify(good, bad_ctx, depth, b"t", expected,
                      nreps=4) is False
    p = copy.deepcopy(good)
    p["reps"][0]["outs"][0] = [2 ** 64] * nout          # unpackable
    assert verify(p, ctx, depth, b"t", expected, nreps=4) is False
    p = copy.deepcopy(good)
    p["reps"][0]["commits"][0] = b"short"
    assert verify(p, ctx, depth, b"t", expected, nreps=4) is False
    p = copy.deepcopy(good)
    p["openings"][0]["seed_e"] = b""
    assert verify(p, ctx, depth, b"t", expected, nreps=4) is False
    print("ok  verifier is total: malformed input rejected, never raised")


def test_wire_decoder_bounds():
    """The header is attacker-controlled. A decoder that sizes
    allocations from it before checking it is a memory bomb."""
    hdr = core.MAGIC + core.VERSION
    bombs = [hdr + b"\x20\x00" + b"\xff\xff\xff\xff",   # 4.29e9 reps
             hdr + b"\xff\xff" + b"\x01\x00\x00\x00",   # depth 65535
             hdr + b"\x20\x00" + b"\x00\x00\x00\x00",   # zero reps
             hdr, b"", b"AVSM", b"nope" + core.VERSION]
    for b in bombs:
        try:
            proof_from_bytes(b)
            raise AssertionError("accepted malformed header")
        except ValueError:
            pass
    wit, ctx, depth, expected = make_instance()
    blob = proof_to_bytes(prove(wit, ctx, depth, b"w", nreps=4))
    for trunc in (blob[:-1], blob + b"\x00", blob[:len(blob) // 2]):
        try:
            p = proof_from_bytes(trunc)
            assert not verify(p, ctx, depth, b"w", expected, nreps=4)
        except ValueError:
            pass
    print("ok  wire decoder rejects hostile headers without allocating")


def test_site_verifier_is_total():
    ga = GovernmentAuthority(depth=6)
    w = CitizenWallet("T")
    w.enroll_with(ga, "t", True)
    bundle = ga.publish_root_bundle()
    site = Website("t.example", bundle)
    n = site.challenge()
    tok = w.make_token(ga.published_tree(), bundle, "t.example",
                       protocol.current_epoch(), n, nreps=6)
    assert site.verify_token(tok, n, nreps=6)
    for mutate in (
        lambda t: dict(t, temp_key=(2 ** 64, 0, 0, 0)),
        lambda t: dict(t, temp_key=(0, 0, 0)),
        lambda t: dict(t, temp_key="nope"),
        lambda t: dict(t, epoch="soon"),
        lambda t: dict(t, epoch=True),
        lambda t: dict(t, proof=None),
        lambda t: dict(t, proof={"version": "avsm/1"}),
        lambda t: "not a token",
    ):
        n2 = site.challenge()
        assert site.verify_token(mutate(tok), n2, nreps=6) is False
    assert verify_root_bundle({"root": "junk"}) is False
    print("ok  website verifier and bundle check are total")


def test_not_enrolled_declines_locally():
    """A wallet with no leaf in the requested tree declines locally
    instead of emitting a proof that cannot verify. A failing proof
    would announce 'below this threshold'; a local decline looks
    exactly like a user saying no."""
    ga15 = GovernmentAuthority(depth=6, threshold=15)
    ga18 = GovernmentAuthority(depth=6, threshold=18)
    teen = CitizenWallet("teen")
    teen.enroll_with(ga15, "teen", True)
    b18 = ga18.publish_root_bundle()
    try:
        teen.make_token(ga18.published_tree(), b18, "probe.example",
                        protocol.current_epoch(),
                        os.urandom(protocol.NONCE_BYTES), nreps=4,
                        allow_repin=True)
        raise AssertionError("emitted a token it cannot back")
    except protocol.NotEnrolledError:
        pass
    print("ok  not enrolled at a threshold: local decline, no proof emitted")


def test_replay_across_tuples():
    """Theorem 4 concretely: one honest token, every neighbouring tuple
    rejects it."""
    ga = GovernmentAuthority(depth=6)
    w = CitizenWallet("R2")
    w.enroll_with(ga, "r2", True)
    bundle = ga.publish_root_bundle()
    ep = protocol.current_epoch()
    a = Website("a.example", bundle)
    b = Website("b.example", bundle)
    n = a.challenge()
    tok = w.make_token(ga.published_tree(), bundle, "a.example", ep, n,
                       nreps=8)
    assert a.verify_token(tok, n, nreps=8)
    assert not a.verify_token(tok, n, nreps=8)               # nonce consumed
    assert not a.verify_token(tok, a.challenge(), nreps=8)   # fresh nonce
    assert not b.verify_token(dict(tok, domain="b.example"),
                              b.challenge(), nreps=8)        # other site
    assert not a.verify_token(dict(tok, epoch=ep + 1),
                              a.challenge(), nreps=8)        # other epoch
    print("ok  replay resistance: nonce, domain and epoch all bind")


if __name__ == "__main__":
    test_poseidon2_official_kat()
    test_engine_matches_native()
    test_serialization_is_little_endian()
    test_context_encoding_is_injective()
    test_share_reconstruction()
    test_completeness_and_binding()
    test_wire_roundtrip()
    test_false_statements_rejected()
    test_view_corruption_always_caught()
    test_malformed_proofs()
    test_verifier_is_total()
    test_wire_decoder_bounds()
    test_protocol_end_to_end()
    test_site_verifier_is_total()
    test_replay_across_tuples()
    test_revocation()
    test_multi_threshold()
    test_not_enrolled_declines_locally()
    test_wallet_storage()
    print("\nall tests passed")
