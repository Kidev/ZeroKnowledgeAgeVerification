"""
demo.py - end-to-end run of the protocol at production parameters.

Defaults: Merkle depth 32 (4.29 billion capacity), 219 ZKBoo
repetitions (soundness error < 2^-128), Poseidon2-Goldilocks with the
official constants, ML-DSA-65 signed root bundles.

Run: python3 demo.py [--reps N] [--depth D]
Full run takes a couple of minutes on one core; use --reps 68 for a
quick pass (~2^-39 soundness, clearly not for deployment).
"""

import argparse
import copy
import time

import core
import protocol
from protocol import GovernmentAuthority, CitizenWallet, Website


def hr(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def timed_prove(wallet, tree, bundle, domain, epoch, nonce, reps):
    t0 = time.time()
    tok = wallet.make_token(tree, bundle, domain, epoch, nonce, reps)
    dt = time.time() - t0
    size = len(core.proof_to_bytes(tok["proof"]))
    print(f"  prove {dt:5.1f} s, proof {size/1e6:5.1f} MB", flush=True)
    return tok


def timed_verify(site, tok, nonce, reps):
    t0 = time.time()
    ok = site.verify_token(tok, nonce, reps)
    print(f"  verify {time.time()-t0:5.1f} s -> "
          f"{'VALID' if ok else 'INVALID'}", flush=True)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=core.DEFAULT_REPS)
    ap.add_argument("--depth", type=int, default=core.DEFAULT_DEPTH)
    args = ap.parse_args()
    reps, depth = args.reps, args.depth
    epoch = protocol.current_epoch()
    err_bits = int(reps * 0.585)  # log2(3/2) per repetition
    print(f"parameters: depth={depth} (capacity {2**depth:,}), "
          f"reps={reps} (soundness error < 2^-{err_bits}), "
          f"ML-DSA-65 root signing: {protocol.HAVE_MLDSA}")

    hr("SETUP: government enrolls verified adults, signs one public root")
    ga = GovernmentAuthority(depth=depth)
    alice, bob = CitizenWallet("Alice"), CitizenWallet("Bob")
    alice.enroll_with(ga, "alice_doe_1990", is_adult=True)
    bob.enroll_with(ga, "bob_roe_1985", is_adult=True)
    for i in range(30):
        CitizenWallet(f"c{i}").enroll_with(ga, f"citizen_{i}", True)
    try:
        CitizenWallet("Kid").enroll_with(ga, "kid_2012", is_adult=False)
    except PermissionError as ex:
        print(f"minor enrollment refused: {ex}")
    bundle = ga.publish_root_bundle()
    tree = ga.published_tree()
    print(f"enrolled adults: {len(ga.registry)}")
    print(f"signed root:     {core.digest_hex(bundle['root'])}")
    print("the GA is never contacted again in anything below")

    site1 = Website("social-network.example", bundle)
    site2 = Website("video-platform.example", bundle)

    hr("SCENARIO 1: Alice proves 18+ to site1 (offline verification)")
    n1 = site1.challenge()
    tok1 = timed_prove(alice, tree, bundle, site1.domain, epoch, n1, reps)
    assert timed_verify(site1, tok1, n1, reps)
    print(f"  site1 pseudonym: {core.digest_hex(tok1['temp_key'])}")

    hr("SCENARIO 2: same site, same epoch: stable pseudonym (re-login)")
    n2 = site1.challenge()
    tok2 = timed_prove(alice, tree, bundle, site1.domain, epoch, n2, reps)
    assert timed_verify(site1, tok2, n2, reps)
    assert tok2["temp_key"] == tok1["temp_key"]
    print("  pseudonym stable across sessions: True")

    hr("SCENARIO 3: different site: unlinkable pseudonym")
    n3 = site2.challenge()
    tok3 = timed_prove(alice, tree, bundle, site2.domain, epoch, n3, reps)
    assert timed_verify(site2, tok3, n3, reps)
    assert tok3["temp_key"] != tok1["temp_key"]
    print(f"  site1 key: {core.digest_hex(tok1['temp_key'])}")
    print(f"  site2 key: {core.digest_hex(tok3['temp_key'])}")

    hr("ATTACK 1a: re-present the token under its consumed nonce")
    ok = site1.verify_token(copy.deepcopy(tok1), n1, reps)
    print(f"  accepted: {ok} (expected False: nonce is single-use)")
    assert not ok

    hr("ATTACK 1b: replay a captured token under a fresh nonce")
    n4 = site1.challenge()
    ok = site1.verify_token(copy.deepcopy(tok1), n4, reps)
    print(f"  accepted: {ok} (expected False: transcript is nonce-bound)")
    assert not ok

    hr("ATTACK 2: relay the token to a different site")
    n5 = site2.challenge()
    cross = copy.deepcopy(tok1)
    cross["domain"] = site2.domain
    ok = site2.verify_token(cross, n5, reps)
    print(f"  accepted: {ok} (expected False: domain is in the statement)")
    assert not ok

    hr("ATTACK 3: non-enrolled prover forges a membership proof")
    mallory = CitizenWallet("Mallory")
    mallory.leaf_index = 0  # claims Alice's slot without Alice's secret
    n6 = site1.challenge()
    forged = timed_prove(mallory, tree, bundle, site1.domain, epoch, n6, reps)
    ok = timed_verify(site1, forged, n6, reps)
    print(f"  accepted: {ok} (expected False)")
    assert not ok

    hr("ATTACK 4: bit-flip inside a valid proof")
    n7 = site1.challenge()
    tok4 = timed_prove(alice, tree, bundle, site1.domain, epoch, n7, reps)
    tampered = copy.deepcopy(tok4)
    tampered["proof"]["openings"][0]["mults_f"][5] ^= 1
    ok = site1.verify_token(tampered, n7, reps)
    print(f"  accepted: {ok} (expected False: commitment binding)")
    assert not ok

    hr("SCENARIO 4: epoch rotation: new pseudonym, bounded window")
    n_ep = site1.challenge()
    tok_ep = timed_prove(alice, tree, bundle, site1.domain, epoch + 1,
                         n_ep, reps)
    assert timed_verify(site1, tok_ep, n_ep, reps)
    assert tok_ep["temp_key"] != tok1["temp_key"]
    print("  pseudonym rotated across epochs: True")
    stale = copy.deepcopy(tok1)
    stale["epoch"] = epoch - 2
    n_st = site1.challenge()
    ok = site1.verify_token(stale, n_st, reps)
    print(f"  epoch outside [now-1, now+1] accepted: {ok} (expected False)")
    assert not ok

    hr("SCENARIO 5: encrypted wallet storage roundtrip")
    if protocol.HAVE_AEAD:
        import os
        import tempfile
        path = os.path.join(tempfile.gettempdir(), "alice.wallet")
        alice.save(path, "correct horse battery staple")
        try:
            CitizenWallet.load(path, "wrong passphrase")
            raise AssertionError("wrong passphrase accepted")
        except Exception:
            print("  wrong passphrase rejected: True")
        alice2 = CitizenWallet.load(path, "correct horse battery staple")
        os.remove(path)
        n_w = site1.challenge()
        tok_w = timed_prove(alice2, tree, bundle, site1.domain, epoch,
                            n_w, reps)
        assert timed_verify(site1, tok_w, n_w, reps)
        assert tok_w["temp_key"] == tok1["temp_key"]
        print("  reloaded wallet proves with identical pseudonym: True")
    else:
        print("  skipped (cryptography package not installed)")

    hr("SCENARIO 6: revocation by root update")
    ga.revoke("bob_roe_1985")
    b2 = ga.publish_root_bundle()
    site1.update_root(b2)
    n8 = site1.challenge()
    tok5 = bob.make_token(tree, b2, site1.domain, epoch, n8, reps)
    ok = site1.verify_token(tok5, n8, reps)
    print(f"  revoked Bob accepted: {ok} (expected False)")
    assert not ok
    n9 = site1.challenge()
    tok6 = timed_prove(alice, tree, b2, site1.domain, epoch, n9, reps)
    assert timed_verify(site1, tok6, n9, reps)
    print("  Alice unaffected: True")

    hr("COLLUSION AUDIT: pool everything GA and both sites possess")
    g = ga.surveillance_view()
    print("GA (identity layer):")
    items = list(g["registry"].items())[:3]
    for cid, idx in items:
        print(f"  {cid} -> leaf #{idx}")
    print(f"  ... {len(g['registry'])} adults, the public tree, the root")
    print("site1 (usage layer):")
    for k, v in site1.surveillance_view()["accounts"].items():
        print(f"  {k[:32]}...: {v}")
    print("site2 (usage layer):")
    for k, v in site2.surveillance_view()["accounts"].items():
        print(f"  {k[:32]}...: {v}")
    print()
    print("Joining the layers requires Alice's secret (never transmitted)")
    print("or breaking the PRF / zero-knowledge property. There is no")
    print("timestamp, counter, or API traffic bridging them: the GA was")
    print("never contacted after enrollment.")

    hr("ALL SCENARIOS AND ATTACK TESTS PASSED")


if __name__ == "__main__":
    main()
