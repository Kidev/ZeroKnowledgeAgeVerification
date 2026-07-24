"""
protocol.py - the three protocol actors.

Structural invariant: the Government Authority appears in exactly one
flow (enrollment) and publishes exactly one artifact (a signed root
bundle). It is never contacted during verification, so it cannot
observe usage even if malicious. Websites verify tokens offline.

Root bundles are signed with ML-DSA-65 (FIPS 204), a NIST-standardized
post-quantum signature. Wallet files are encrypted at rest with
scrypt-derived keys and AES-256-GCM.

Replay resistance (paper, Theorem 4) and threshold isolation (paper,
Proposition 1) both rest on one syntactic fact: the map

    (domain, epoch, root, temp_key, nonce) -> token_context_bytes(...)

is injective. It is, because every field after the domain has a fixed
width and the domain itself may not contain the separator. That is not
a property of hostnames we are willing to assume silently, so it is
checked (_check_domain) on both the proving and the verifying side.
"""

import hashlib
import json
import os
import secrets
import struct
import time

import core

try:
    from dilithium_py.ml_dsa import ML_DSA_65
    HAVE_MLDSA = True
except ImportError:
    HAVE_MLDSA = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AEAD = True
except ImportError:
    HAVE_AEAD = False


EPOCH_SECONDS = 30 * 24 * 3600
NONCE_TTL_SECONDS = 600
NONCE_BYTES = 16

CTX_SEP = "|"        # field separator inside the Fiat-Shamir context
THRESHOLD_SEP = "#"  # folds the age threshold into the domain field


def current_epoch(now=None) -> int:
    return int((time.time() if now is None else now) // EPOCH_SECONDS)


def _check_domain(domain):
    """A raw hostname: free of both separators. Neither can occur in a
    hostname, but a caller controls this string, so we enforce rather
    than assume. This is the inner half of the injectivity argument:
    (domain, threshold) -> domain#threshold is injective because the
    domain contributes no '#' of its own."""
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty string")
    for bad in (CTX_SEP, THRESHOLD_SEP):
        if bad in domain:
            raise ValueError(f"domain may not contain {bad!r}")
    return domain


def _check_ctx_field(field):
    """The composed domain field, either 'domain' or 'domain#threshold'.
    Outer half of the injectivity argument: it carries no CTX_SEP, so
    the context byte string parses back to exactly one field, and it
    holds at most one THRESHOLD_SEP, so the field parses back to exactly
    one (domain, threshold)."""
    if not isinstance(field, str) or not field:
        raise ValueError("context domain field must be a non-empty string")
    if CTX_SEP in field:
        raise ValueError(f"context domain field may not contain {CTX_SEP!r}")
    parts = field.split(THRESHOLD_SEP)
    if len(parts) > 2 or not parts[0] or (len(parts) == 2
                                          and not parts[1].isdigit()):
        raise ValueError("malformed context domain field")
    return field


def ctx_domain(domain: str, threshold) -> str:
    # Folds the age threshold into the context string. '#' cannot occur
    # in a hostname and is rejected above, so (domain, threshold) maps
    # injectively into the domain field, and threshold=None reproduces
    # the single-set context byte for byte. Both sides derive this
    # independently from their own (domain, threshold), so a token made
    # for one threshold fails cryptographically against any other: the
    # circuit's public context and expected outputs no longer match.
    _check_domain(domain)
    if threshold is None:
        return domain
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or not 0 <= threshold < 1 << 16:
        raise ValueError("threshold must be a small non-negative integer")
    return f"{domain}{THRESHOLD_SEP}{threshold}"


def token_context_bytes(domain, epoch, root, temp_key, nonce) -> bytes:
    """The Fiat-Shamir context. Injective in its arguments: the domain
    field carries no separator and every later field has a fixed width,
    so the byte string parses back to exactly one tuple. `domain` here
    is the composed field, i.e. the output of ctx_domain."""
    _check_ctx_field(domain)
    if not isinstance(epoch, int) or isinstance(epoch, bool) \
            or not 0 <= epoch < 1 << 64:
        raise ValueError("epoch out of range")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    return (b"avsm-token/1|" + domain.encode() + b"|"
            + struct.pack("<Q", epoch) + b"|" + core.ser_digest(root)
            + b"|" + core.ser_digest(temp_key) + b"|" + bytes(nonce))


def _bundle_message(root, tree_size: int, issued_at: int, depth: int,
                    threshold=None) -> bytes:
    # threshold=None: single-set deployment, v1 message (default).
    # threshold=a: multi-threshold deployment, one accumulator per age
    # threshold; the threshold is bound under the signature so a root
    # cannot be presented as certifying a different threshold.
    if threshold is None:
        return (b"avsm-root-bundle/1|" + core.ser_digest(root)
                + struct.pack("<QQH", tree_size, issued_at, depth))
    return (b"avsm-root-bundle/2|" + core.ser_digest(root)
            + struct.pack("<QQHH", tree_size, issued_at, depth, threshold))


class GovernmentAuthority:
    """Enrolls verified citizens into a public Merkle set and signs the
    root. Knows citizen_id <-> leaf index. That mapping is harmless:
    the leaf never reappears anywhere observable.

    threshold=None runs the single-set deployment ("of age": yes).
    A jurisdiction with several legal thresholds (13, 15, 16, 18, ...)
    runs one instance per threshold, inserting a citizen's commitment
    (the same leaf, from the same wallet secret) into every tree whose
    threshold the citizen satisfies; each bundle then carries its
    threshold, bound under the signature. In production the instances
    share one signing key; separate keys here keep the demo simple."""

    def __init__(self, depth=core.DEFAULT_DEPTH, threshold=None):
        self.tree = core.SparseMerkleTree(depth)
        self.registry = {}   # citizen_id -> leaf index
        self.depth = depth
        self.threshold = threshold
        if HAVE_MLDSA:
            self.pk, self._sk = ML_DSA_65.keygen()
        else:
            self.pk, self._sk = None, None

    def enroll(self, citizen_id: str, is_adult: bool, leaf) -> int:
        if not is_adult:
            raise PermissionError("citizen is not of age, enrollment refused")
        if citizen_id in self.registry:
            raise PermissionError("citizen already enrolled")
        idx = self.tree.append(leaf)
        self.registry[citizen_id] = idx
        return idx

    def revoke(self, citizen_id: str):
        idx = self.registry.pop(citizen_id, None)
        if idx is None:
            raise KeyError("not enrolled")
        self.tree.revoke(idx)

    def publish_root_bundle(self):
        """The single public artifact. In deployment it is mirrored and
        gossiped (transparency-log style) so the GA cannot serve
        split-view roots to individual users."""
        root = self.tree.root()
        issued = int(time.time())
        msg = _bundle_message(root, self.tree.next_index, issued, self.depth,
                              self.threshold)
        sig = ML_DSA_65.sign(self._sk, msg) if HAVE_MLDSA else b""
        bundle = {"root": root, "tree_size": self.tree.next_index,
                  "issued_at": issued, "depth": self.depth,
                  "signature": sig, "ga_public_key": self.pk}
        if self.threshold is not None:
            bundle["threshold"] = self.threshold
        return bundle

    def published_tree(self):
        # public data; wallets sync it in bulk (or via PIR) so path
        # retrieval leaks nothing about which leaf is theirs
        return self.tree

    def surveillance_view(self):
        return {"registry": dict(self.registry),
                "root": self.tree.root()}


def _bundle_is_well_formed(bundle) -> bool:
    """Structure only, no cryptography. Kept separate from the signature
    check so that a malformed bundle is rejected even in the demo
    fallback below: 'we cannot check the signature' is not a reason to
    accept an object that is not a bundle in the first place."""
    if not isinstance(bundle, dict):
        return False
    if not core._canonical(bundle.get("root"), 4):
        return False
    for key, hi in (("tree_size", 1 << 64), ("issued_at", 1 << 64)):
        v = bundle.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < hi:
            return False
    depth = bundle.get("depth")
    if not isinstance(depth, int) or isinstance(depth, bool) \
            or not 1 <= depth <= core.MAX_DEPTH:
        return False
    threshold = bundle.get("threshold")
    if threshold is not None:
        if not isinstance(threshold, int) or isinstance(threshold, bool) \
                or not 0 <= threshold < 1 << 16:
            return False
    return True


def verify_root_bundle(bundle) -> bool:
    """Total: any malformed bundle is an invalid bundle."""
    try:
        if not _bundle_is_well_formed(bundle):
            return False
        if not HAVE_MLDSA:
            # Demo fallback. Deployment requires the signature; this
            # branch exists so the protocol can be exercised without the
            # optional dependency, and it still refuses anything that is
            # not shaped like a bundle.
            return True
        msg = _bundle_message(bundle["root"], bundle["tree_size"],
                              bundle["issued_at"], bundle["depth"],
                              bundle.get("threshold"))
        return bool(ML_DSA_65.verify(bundle["ga_public_key"], msg,
                                     bundle["signature"]))
    except Exception:
        return False


class ThresholdChangeWarning(ValueError):
    """Raised when a domain requests a different age threshold than the
    one it previously declared. The wallet UI shows what the site wants
    to check; on a change it must surface this warning and proceed only
    on deliberate user confirmation (allow_repin=True). The default is
    refusal, and the warning fires before any membership-dependent step,
    identically for every wallet regardless of the holder's age."""


class NotEnrolledError(RuntimeError):
    """The wallet holds no leaf in the tree it is being asked to prove
    against. It declines locally instead of emitting a proof that
    cannot verify: a proof that fails verification would tell the site
    'this holder is below that threshold', whereas a local decline is
    indistinguishable, from the site's side, from a user who simply
    said no. Two observable outcomes instead of three."""


class CitizenWallet:
    """Local, open source. Holds the only secret in the system: 256
    bits of locally generated randomness, never transmitted."""

    SCRYPT_N = 1 << 15
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(self, name: str, secret=None):
        self.name = name
        self.secret = tuple(secret) if secret else core.rand_digest()
        self.leaf_index = None
        self.indices = {}    # threshold -> leaf index in that tree
        self.pins = {}       # domain -> pinned threshold

    def commitment(self):
        return core.leaf_hash_native(self.secret)

    def enroll_with(self, ga: GovernmentAuthority, citizen_id: str,
                    is_adult: bool):
        # The commitment is the same in every tree the citizen qualifies
        # for, but each tree fills independently, so the index is not.
        # The wallet keeps one index per threshold.
        idx = ga.enroll(citizen_id, is_adult, self.commitment())
        self.indices[ga.threshold] = idx
        if self.leaf_index is None or ga.threshold is None:
            self.leaf_index = idx
        return idx

    def requested_check(self, root_bundle):
        # What the wallet UI displays before proving: the age threshold
        # this bundle would check, or None for a single-set deployment.
        return root_bundle.get("threshold")

    def make_token(self, tree, root_bundle, domain: str, epoch: int,
                   nonce: bytes, nreps=core.DEFAULT_REPS,
                   allow_repin=False):
        if not verify_root_bundle(root_bundle):
            raise ValueError("root bundle signature invalid")
        threshold = root_bundle.get("threshold")
        # One threshold per domain. A change triggers a warning that the
        # UI must surface; proving continues only if the user explicitly
        # confirms. The check runs before anything membership dependent,
        # so the warning is identical for every wallet whatever the
        # holder's age.
        if threshold is not None:
            pinned = self.pins.get(domain)
            if pinned is not None and pinned != threshold and not allow_repin:
                raise ThresholdChangeWarning(
                    f"{domain} previously checked {pinned}+ and now "
                    f"requests {threshold}+; this is how a site "
                    f"would probe your age bracket, refusing "
                    f"without explicit confirmation")
            self.pins[domain] = threshold

        leaf_index = self.indices.get(threshold) if threshold is not None \
            else self.leaf_index
        if leaf_index is None:
            raise NotEnrolledError(
                "no leaf in the requested accumulator; declining locally "
                "rather than emitting a proof that cannot verify")

        depth = tree.depth
        root = root_bundle["root"]
        bits, sibs = tree.path(leaf_index)
        wit = list(self.secret)
        for i in range(depth):
            wit.append(bits[i])
            wit.extend(sibs[i])

        cd = ctx_domain(domain, threshold)
        ctx = core.context_digest(cd, epoch)
        temp_key = core.prf_native(self.secret, ctx)
        ctx_bytes = token_context_bytes(cd, epoch, root, temp_key, nonce)
        proof = core.prove(wit, ctx, depth, ctx_bytes, nreps)
        return {"temp_key": temp_key, "epoch": epoch, "domain": domain,
                "threshold": threshold, "proof": proof}

    # Encrypted storage

    def save(self, path: str, passphrase: str):
        if not HAVE_AEAD:
            raise RuntimeError("cryptography package required for storage")
        salt = os.urandom(16)
        key = hashlib.scrypt(passphrase.encode(), salt=salt,
                             n=self.SCRYPT_N, r=self.SCRYPT_R,
                             p=self.SCRYPT_P, maxmem=64 * 1024 * 1024,
                             dklen=32)
        payload = json.dumps({"name": self.name,
                              "secret": list(self.secret),
                              "leaf_index": self.leaf_index,
                              "indices": {str(k): v for k, v
                                          in self.indices.items()},
                              "pins": self.pins}).encode()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, payload, b"avsm-wallet/1")
        with open(path, "wb") as fh:
            fh.write(b"AVWL\x01" + salt + nonce + ct)

    @classmethod
    def load(cls, path: str, passphrase: str):
        if not HAVE_AEAD:
            raise RuntimeError("cryptography package required for storage")
        with open(path, "rb") as fh:
            blob = fh.read()
        if blob[:5] != b"AVWL\x01":
            raise ValueError("not a wallet file")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        key = hashlib.scrypt(passphrase.encode(), salt=salt,
                             n=cls.SCRYPT_N, r=cls.SCRYPT_R,
                             p=cls.SCRYPT_P, maxmem=64 * 1024 * 1024,
                             dklen=32)
        payload = json.loads(AESGCM(key).decrypt(nonce, ct, b"avsm-wallet/1"))
        w = cls(payload["name"], secret=payload["secret"])
        w.leaf_index = payload["leaf_index"]
        w.indices = {(None if k == "None" else int(k)): v
                     for k, v in payload.get("indices", {}).items()}
        w.pins = payload.get("pins", {})
        return w


class Website:
    """Verifies tokens offline against the GA-signed root bundle. Never
    contacts the government. Learns one bit and a per-site per-epoch
    pseudonym.

    required_threshold pins the site to the accumulator of exactly one
    age threshold. This is not merely policy: the threshold is folded
    into the proof context on both sides, so a token made for one
    threshold fails verification against every other, for every user,
    and a consumed nonce cannot be replayed. Probing a second threshold
    requires a fresh proof, which wallets refuse (one pinned threshold
    per domain)."""

    def __init__(self, domain: str, root_bundle, required_threshold=None):
        self.domain = _check_domain(domain)
        self.required_threshold = required_threshold
        self.accounts = {}   # temp_key -> first_seen
        self.nonces = {}     # nonce -> (issued_at, consumed)
        self._check_bundle(root_bundle)
        self.bundle = root_bundle

    def _check_bundle(self, bundle):
        if not verify_root_bundle(bundle):
            raise ValueError("refusing unsigned/invalid root bundle")
        if bundle.get("threshold") != self.required_threshold:
            raise ValueError("bundle threshold does not match the "
                             "site's required threshold")

    def update_root(self, root_bundle):
        self._check_bundle(root_bundle)
        if root_bundle["issued_at"] < self.bundle["issued_at"]:
            raise ValueError("stale bundle, possible rollback")
        self.bundle = root_bundle

    def challenge(self) -> bytes:
        now = time.time()
        # opportunistic sweep: an unbounded nonce table is a slow leak
        for n, (issued, _) in list(self.nonces.items()):
            if now - issued > NONCE_TTL_SECONDS:
                del self.nonces[n]
        n = secrets.token_bytes(NONCE_BYTES)
        self.nonces[n] = (now, False)
        return n

    def verify_token(self, token, nonce: bytes,
                     nreps=core.DEFAULT_REPS) -> bool:
        """Total: returns False on any malformed token, never raises."""
        try:
            state = self.nonces.get(nonce)
            if state is None or state[1]:
                return False
            if time.time() - state[0] > NONCE_TTL_SECONDS:
                del self.nonces[nonce]
                return False
            if not isinstance(token, dict):
                return False
            if token.get("domain") != self.domain:
                return False
            if token.get("threshold") != self.required_threshold:
                return False
            ep = token.get("epoch")
            if not isinstance(ep, int) or isinstance(ep, bool):
                return False
            if abs(ep - current_epoch()) > 1:
                return False
            tk = token.get("temp_key")
            if not core._canonical(tk, 4):
                return False
            tk = tuple(tk)

            root = self.bundle["root"]
            depth = self.bundle["depth"]
            cd = ctx_domain(self.domain, self.required_threshold)
            ctx = core.context_digest(cd, ep)
            expected = list(tk) + list(root) + [0] * depth
            ctx_bytes = token_context_bytes(cd, ep, root, tk, nonce)
            ok = core.verify(token.get("proof"), ctx, depth, ctx_bytes,
                             expected, nreps)
            if ok:
                self.nonces[nonce] = (state[0], True)
                self.accounts.setdefault(tk, time.time())
            return ok
        except Exception:
            return False

    def surveillance_view(self):
        return {"domain": self.domain,
                "accounts": {core.digest_hex(k): "of age, nothing else"
                             for k in self.accounts}}
