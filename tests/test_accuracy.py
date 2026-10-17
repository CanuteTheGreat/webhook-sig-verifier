"""Detection accuracy: a valid signature must verify (no false rejections) and every kind of
tampering must be caught (no false acceptances), for every scheme, judged against independent
implementations (Python's hmac module, `cryptography`'s Ed25519, RFC 8032's published vectors).
"""
import base64
import hashlib
import hmac
import importlib.util
import os
import random
import subprocess
import sys
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "webhook_sig_verifier.py")
BODY = b'{"id":"evt_9","type":"invoice.paid","data":{"amount":1999,"currency":"usd","note":"caf\xc3\xa9 \\u2603"}}'
SECRET = "s3cr3t-Key_123"
URL = "https://hooks.example.com/in?src=test&x=1"
SW_SECRET = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


def load_tool():
    spec = importlib.util.spec_from_file_location("webhook_sig_verifier", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60)


def h(key, msg, mod=hashlib.sha256):
    return hmac.new(key if isinstance(key, bytes) else key.encode(), msg, mod)


def cases(now):
    """scheme -> (cli args builder(body, secret, sig, ts, url), signer(body, secret, ts, url) -> sig)"""
    ts = str(now)
    return {
        "github": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                   lambda b, s, t, u: "sha256=" + h(s, b).hexdigest()),
        "github-sha1": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                        lambda b, s, t, u: "sha1=" + h(s, b, hashlib.sha1).hexdigest()),
        "stripe": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                   lambda b, s, t, u: "t=%s,v1=%s" % (t, h(s, ("%s." % t).encode() + b).hexdigest())),
        "slack": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig, "--timestamp", t],
                  lambda b, s, t, u: "v0=" + h(s, ("v0:%s:" % t).encode() + b).hexdigest()),
        "zoom": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig, "--timestamp", t],
                 lambda b, s, t, u: "v0=" + h(s, ("v0:%s:" % t).encode() + b).hexdigest()),
        "shopify": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                    lambda b, s, t, u: base64.b64encode(h(s, b).digest()).decode()),
        "square": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig, "--url", u],
                   lambda b, s, t, u: base64.b64encode(h(s, u.encode() + b).digest()).decode()),
        "standard-webhooks": (
            lambda b, s, sig, t, u: ["--secret", s, "--signature", sig, "--timestamp", t, "--webhook-id", "msg_1"],
            lambda b, s, t, u: "v1," + base64.b64encode(
                h(base64.b64decode(s.split("_", 1)[1]), ("msg_1.%s." % t).encode() + b).digest()).decode()),
        "generic-sha256": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                           lambda b, s, t, u: h(s, b).hexdigest()),
        "generic-sha1": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                         lambda b, s, t, u: h(s, b, hashlib.sha1).hexdigest()),
        "generic-sha512": (lambda b, s, sig, t, u: ["--secret", s, "--signature", sig],
                           lambda b, s, t, u: h(s, b, hashlib.sha512).hexdigest()),
    }, ts


class TestHmacSchemes(unittest.TestCase):
    """For each scheme: the genuine signature verifies (exit 0, no warning); each tampering
    (one body byte, one extra space, the secret, the timestamp, the URL, a truncated or
    single-character-changed signature) is rejected (exit 1)."""

    def verify(self, scheme, body, secret, sig, ts, url):
        builder = CASES[scheme][0]
        name = "github" if scheme == "github-sha1" else scheme
        return run("--scheme", name, "--payload", body.decode("utf-8"), *builder(body, secret, sig, ts, url))

    def test_matrix(self):
        global CASES
        now = int(time.time())
        CASES, ts = cases(now)
        rng = random.Random(1016)
        for scheme, (builder, signer) in CASES.items():
            secret = SW_SECRET if scheme == "standard-webhooks" else SECRET
            good = signer(BODY, secret, ts, URL)
            with self.subTest(scheme=scheme, case="genuine"):
                p = self.verify(scheme, BODY, secret, good, ts, URL)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn(b"WARNING", p.stdout)
            i = rng.randrange(len(BODY) - 1)
            flipped = BODY[:i] + bytes([BODY[i] ^ 1]) + BODY[i + 1:]
            tampered = {
                "body byte flipped": dict(body=flipped),
                "trailing space": dict(body=BODY + b" "),
                "other secret": dict(secret=(SW_SECRET[:-6] + "AAAAA=") if scheme == "standard-webhooks"
                                     else SECRET + "x"),
                "signature truncated": dict(sig=good[:-2]),
                # a different character even after the case-insensitive hex comparison
                "signature char changed": dict(sig=good[:-3] + ("0" if good[-3].lower() != "0" else "1") + good[-2:]),
            }
            if scheme in ("stripe", "slack", "zoom", "standard-webhooks"):
                tampered["other timestamp"] = dict(ts=str(now - 1), sig_ts=ts)
            if scheme == "square":
                tampered["other url"] = dict(url=URL + "&y=2")
            for what, change in tampered.items():
                with self.subTest(scheme=scheme, case=what):
                    body = change.get("body", BODY)
                    sec = change.get("secret", secret)
                    t = change.get("ts", ts)
                    u = change.get("url", URL)
                    sig = change.get("sig", good)
                    if scheme == "stripe" and "ts" in change:  # the timestamp lives inside the header
                        sig = good.replace("t=%s" % ts, "t=%s" % t)
                    p = self.verify(scheme, body, sec, sig, t, u)
                    self.assertEqual(p.returncode, 1, (what, p.stdout + p.stderr))

    def test_stale_genuine_signature_is_valid_with_warning(self):
        old = int(time.time()) - 3600
        c, ts = cases(old)
        for scheme in ("stripe", "slack", "zoom", "standard-webhooks"):
            with self.subTest(scheme=scheme):
                secret = SW_SECRET if scheme == "standard-webhooks" else SECRET
                sig = c[scheme][1](BODY, secret, ts, URL)
                p = run("--scheme", scheme, "--payload", BODY.decode(), *c[scheme][0](BODY, secret, sig, ts, URL))
                self.assertEqual(p.returncode, 0)
                self.assertRegex(p.stdout.decode(), r"WARNING: timestamp is 360[0-2]s from now \(tolerance 300s\)")
                p = run("--scheme", scheme, "--payload", BODY.decode(), "--tolerance", "4000",
                        *c[scheme][0](BODY, secret, sig, ts, URL))
                self.assertNotIn(b"WARNING", p.stdout)


# RFC 8032 section 7.1 test vectors (public key, message, signature)
RFC8032 = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]
L = 2 ** 252 + 27742317777372353535851937790883648493


class TestEd25519(unittest.TestCase):
    """The pure-Python RFC 8032 verifier against the RFC's vectors and against OpenSSL's
    Ed25519 (via `cryptography`) on random keys and messages, plus tampering and the
    malleable S + L form, which RFC 8032 requires verifiers to reject."""

    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_rfc8032_vectors(self):
        for pub, msg, sig in RFC8032:
            with self.subTest(msg=msg[:16]):
                pub, msg, sig = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
                self.assertTrue(self.tool.ed25519_verify(pub, msg, sig))
                self.assertFalse(self.tool.ed25519_verify(pub, msg + b"\0", sig))
                s = int.from_bytes(sig[32:], "little")
                self.assertFalse(self.tool.ed25519_verify(pub, msg, sig[:32] + (s + L).to_bytes(32, "little")))

    def test_against_openssl_random(self):
        rng = random.Random(8032)
        for n in range(40):
            key = Ed25519PrivateKey.generate()
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            msg = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
            sig = key.sign(msg)
            with self.subTest(n=n):
                self.assertTrue(self.tool.ed25519_verify(pub, msg, sig))
                bit = rng.randrange(512)
                bad = bytearray(sig)
                bad[bit // 8] ^= 1 << (bit % 8)
                self.assertFalse(self.tool.ed25519_verify(pub, msg, bytes(bad)))
                other = Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertFalse(self.tool.ed25519_verify(other, msg, sig))
                self.assertFalse(self.tool.ed25519_verify(pub, msg[:-1] if msg else b"x", sig))
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = key.sign(b"")
        self.assertFalse(self.tool.ed25519_verify(b"\0" * 31, b"", b"\0" * 64))
        self.assertFalse(self.tool.ed25519_verify(pub, b"", sig[:63]))
        # y >= p (non-canonical) public key encoding is rejected
        self.assertFalse(self.tool.ed25519_verify(b"\xff" * 31 + b"\x7f", b"", sig))

    def test_cli_v1a_end_to_end(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ts = str(int(time.time()))
        sig = "v1a," + base64.b64encode(key.sign(("msg_9.%s." % ts).encode() + BODY)).decode()
        args = ["--scheme", "standard-webhooks", "--secret", "whpk_" + base64.b64encode(pub).decode(),
                "--webhook-id", "msg_9", "--timestamp", ts, "--payload", BODY.decode()]
        self.assertEqual(run(*args, "--signature", sig).returncode, 0)
        self.assertEqual(run(*args, "--signature", "v1," + sig.split(",")[1]).returncode, 1)  # v1 != v1a


if __name__ == "__main__":
    unittest.main()
