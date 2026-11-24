"""Golden tests: the exact notes, error wording, boundaries and parsing of every verifier, called
in-process (the tool module is imported, so mutmut can tell which test exercises which function).
Expected MACs are computed here with Python's hmac/hashlib, never with the tool's own code paths.
"""
import base64
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "webhook_sig_verifier.py")


def load_tool():
    spec = importlib.util.spec_from_file_location("webhook_sig_verifier", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T = load_tool()
BODY = b'{"a":1}'
SECRET = "s3cr3t"
NOW = 1700000000


def hx(key, data, algo=hashlib.sha256):
    return hmac.new(key, data, algo).hexdigest()


def b64(key, data, algo=hashlib.sha256):
    return base64.b64encode(hmac.new(key, data, algo).digest()).decode()


def cli(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if stdin is not None:
            fake = mock.Mock()
            fake.buffer = io.BytesIO(stdin)
            with mock.patch.object(T.sys, "stdin", fake):
                try:
                    rc = T.main(argv)
                except SystemExit as e:
                    rc = e.code
        else:
            try:
                rc = T.main(argv)
            except SystemExit as e:
                rc = e.code
    return rc, out.getvalue(), err.getvalue()


class AgeWarning(unittest.TestCase):
    def test_not_an_integer(self):
        self.assertEqual(T._age_warning("abc", 300, "X"), "WARNING: timestamp is not a valid integer")
        self.assertEqual(T._age_warning(None, 300, "X"), "WARNING: timestamp is not a valid integer")

    def test_boundary_and_message(self):
        with mock.patch.object(T.time, "time", return_value=1000.0):
            self.assertIsNone(T._age_warning("700", 300, "X"))      # exactly the tolerance: fine
            self.assertEqual(T._age_warning("699", 300, "Who"),
                             "WARNING: timestamp is 301s from now (tolerance 300s) -- Who would reject this as a possible replay")
            self.assertIsNone(T._age_warning("1300", 300, "X"))
            self.assertIsNotNone(T._age_warning("1301", 300, "X"))


class B64Eq(unittest.TestCase):
    def test_strict_decoding(self):
        self.assertTrue(T._b64eq(b"ABC", "QUJD"))
        self.assertTrue(T._b64eq(b"ABC", "  QUJD\n"))
        self.assertFalse(T._b64eq(b"ABC", "QU*JD"))   # junk is rejected, not skipped
        self.assertFalse(T._b64eq(b"ABC", "QUJ"))
        self.assertFalse(T._b64eq(b"ABC", "QUJE"))


class Github(unittest.TestCase):
    def test_messages(self):
        self.assertEqual(T.verify_github(BODY, SECRET, "nosign"),
                         (False, ["malformed signature: expected 'sha256=<hex>' or 'sha1=<hex>'"]))
        self.assertEqual(T.verify_github(BODY, SECRET, "md5=ab"),
                         (False, ["unsupported algo 'md5' (GitHub uses sha256, legacy sha1)"]))

    def test_split_on_first_equals(self):
        ok, notes = T.verify_github(BODY, SECRET, "sha256=ab=cd")
        self.assertFalse(ok)
        self.assertEqual(notes, ["computed sha256=" + hx(SECRET.encode(), BODY)])

    def test_valid_and_legacy(self):
        e = hx(SECRET.encode(), BODY)
        self.assertEqual(T.verify_github(BODY, SECRET, "sha256=" + e.upper()), (True, ["computed sha256=" + e]))
        e1 = hx(SECRET.encode(), BODY, hashlib.sha1)
        self.assertEqual(T.verify_github(BODY, SECRET, "sha1= " + e1 + " "), (True, ["computed sha1=" + e1]))
        self.assertFalse(T.verify_github(BODY, SECRET, "sha1=" + e)[0])
        self.assertFalse(T.verify_github(BODY, SECRET, "sha256=" + e1)[0])

    def test_non_ascii_secret(self):
        s = "sécret-\u2603"
        self.assertTrue(T.verify_github(BODY, s, "sha256=" + hx(s.encode("utf-8"), BODY))[0])


class Stripe(unittest.TestCase):
    def sig(self, ts=NOW, secret=SECRET, body=BODY):
        return hx(secret.encode(), ("%s." % ts).encode() + body)

    def test_malformed(self):
        for s in ("", "t=1", "v1=ab", "t=,v1=ab", "junk"):
            self.assertEqual(T.verify_stripe(BODY, SECRET, s),
                             (False, ["malformed signature: expected 't=...,v1=...'"]), s)

    def test_valid_notes_and_tolerance_message(self):
        v1 = self.sig()
        with mock.patch.object(T.time, "time", return_value=float(NOW)):
            self.assertEqual(T.verify_stripe(BODY, SECRET, "t=%d,v1=%s" % (NOW, v1)), (True, ["computed v1=" + v1]))
        with mock.patch.object(T.time, "time", return_value=float(NOW + 1000)):
            ok, notes = T.verify_stripe(BODY, SECRET, "t=%d,v1=%s" % (NOW, v1))
            self.assertTrue(ok)
            self.assertEqual(notes, ["computed v1=" + v1,
                                     "WARNING: timestamp is 1000s from now (tolerance 300s) -- "
                                     "Stripe's own libraries would reject this as a possible replay"])
            self.assertEqual(len(T.verify_stripe(BODY, SECRET, "t=%d,v1=%s" % (NOW, v1), tolerance=1000)[1]), 1)

    def test_multiple_v1_and_spacing(self):
        v1 = self.sig()
        ok, _ = T.verify_stripe(BODY, SECRET, "t=%d, v1=%s ,v1=%s,v0=zz" % (NOW, "0" * 64, v1.upper()))
        self.assertTrue(ok)
        self.assertFalse(T.verify_stripe(BODY, SECRET, "t=%d,v1=%s" % (NOW, "0" * 64))[0])

    def test_value_containing_equals(self):
        # only the first '=' splits: the value keeps the rest, and the parse does not blow up
        ok, notes = T.verify_stripe(BODY, SECRET, "t=%d,v1=ab=cd" % NOW)
        self.assertFalse(ok)
        self.assertTrue(notes[0].startswith("computed v1="))
        v1 = hx(SECRET.encode(), b"1=2." + BODY)
        self.assertTrue(T.verify_stripe(BODY, SECRET, "t=1=2,v1=" + v1)[0])

    def test_non_ascii(self):
        s, b = "sécret", "payload \u2603".encode("utf-8")
        self.assertTrue(T.verify_stripe(b, s, "t=%d,v1=%s" % (NOW, self.sig(secret=s, body=b)))[0])


class V0Schemes(unittest.TestCase):
    def sig(self, ts=NOW, body=BODY, secret=SECRET):
        return "v0=" + hx(secret.encode(), ("v0:%s:" % ts).encode() + body)

    def test_messages(self):
        self.assertEqual(T.verify_slack(BODY, SECRET, "v0=ab"), (False, ["Slack scheme requires --timestamp"]))
        self.assertEqual(T.verify_zoom(BODY, SECRET, "v0=ab"), (False, ["Zoom scheme requires --timestamp"]))
        self.assertEqual(T.verify_zoom(BODY, SECRET, "v0=ab", timestamp=""), (False, ["Zoom scheme requires --timestamp"]))
        self.assertEqual(T.verify_slack(BODY, SECRET, "ab", timestamp="1"),
                         (False, ["malformed signature: expected 'v0=<hex>'"]))
        self.assertEqual(T.verify_zoom(BODY, SECRET, "V0=ab", timestamp="1"),
                         (False, ["malformed signature: expected 'v0=<hex>'"]))

    def test_valid_notes(self):
        sig = self.sig()
        with mock.patch.object(T.time, "time", return_value=float(NOW)):
            for fn in (T.verify_slack, T.verify_zoom):
                self.assertEqual(fn(BODY, SECRET, sig, timestamp=str(NOW)), (True, ["computed " + sig]))
                self.assertEqual(fn(BODY, SECRET, sig.upper().replace("V0=", "v0="), timestamp=str(NOW))[0], True)
                self.assertFalse(fn(BODY, SECRET, sig[:-1] + ("0" if sig[-1] != "0" else "1"), timestamp=str(NOW))[0])
                self.assertFalse(fn(BODY, SECRET, sig, timestamp=str(NOW + 1))[0])

    def test_replay_warning_names_the_provider(self):
        sig = self.sig()
        with mock.patch.object(T.time, "time", return_value=float(NOW + 301)):
            self.assertEqual(T.verify_slack(BODY, SECRET, sig, timestamp=str(NOW))[1][1],
                             "WARNING: timestamp is 301s from now (tolerance 300s) -- "
                             "Slack's guidance would reject this as a possible replay")
            self.assertEqual(T.verify_zoom(BODY, SECRET, sig, timestamp=str(NOW))[1][1],
                             "WARNING: timestamp is 301s from now (tolerance 300s) -- "
                             "Zoom's guidance would reject this as a possible replay")
            self.assertEqual(len(T.verify_zoom(BODY, SECRET, sig, timestamp=str(NOW), tolerance=301)[1]), 1)

    def test_non_ascii(self):
        s, b = "sécret", "x\u2603".encode("utf-8")
        self.assertTrue(T.verify_zoom(b, s, self.sig(body=b, secret=s), timestamp=str(NOW))[0])


class Shopify(unittest.TestCase):
    def test_valid_and_notes(self):
        m = b64(SECRET.encode(), BODY)
        self.assertEqual(T.verify_shopify(BODY, SECRET, m), (True, ["computed " + m]))
        self.assertFalse(T.verify_shopify(BODY, SECRET, "!!" + m)[0])
        s = "sécret"
        self.assertTrue(T.verify_shopify(BODY, s, b64(s.encode("utf-8"), BODY))[0])


class Square(unittest.TestCase):
    URL = "https://example.com/hook"

    def test_missing_url(self):
        self.assertEqual(T.verify_square(BODY, SECRET, "x"),
                         (False, ["square scheme requires --url (the notification URL configured in Square)"]))
        self.assertEqual(T.verify_square(BODY, SECRET, "x", url=""),
                         (False, ["square scheme requires --url (the notification URL configured in Square)"]))

    def test_valid(self):
        m = b64(SECRET.encode(), self.URL.encode() + BODY)
        self.assertEqual(T.verify_square(BODY, SECRET, m, url=self.URL), (True, ["computed " + m]))
        self.assertFalse(T.verify_square(BODY, SECRET, m, url=self.URL + "/")[0])
        u, s = "https://exämple.com/\u2603", "sécret"
        self.assertTrue(T.verify_square(BODY, s, b64(s.encode("utf-8"), u.encode("utf-8") + BODY), url=u)[0])


class Twilio(unittest.TestCase):
    URL = "https://example.com/sms"

    def test_missing_url(self):
        self.assertEqual(T.verify_twilio(b"a=1", SECRET, "x"),
                         (False, ["twilio scheme requires --url (the full URL Twilio requested, including any query string)"]))

    def test_form_params_sorted_with_blanks(self):
        m = b64(SECRET.encode(), (self.URL + "Body" + "hi" + "Empty" + "" + "From" + "+1").encode(), hashlib.sha1)
        ok, notes = T.verify_twilio(b"From=%2B1&Empty=&Body=hi", SECRET, m, url=self.URL)
        self.assertEqual((ok, notes), (True, ["computed " + m]))

    def test_invalid_utf8_body_is_replaced(self):
        m = b64(SECRET.encode(), (self.URL + "a" + "\ufffd").encode("utf-8"), hashlib.sha1)
        self.assertEqual(T.verify_twilio(b"a=\xff", SECRET, m, url=self.URL), (True, ["computed " + m]))

    def test_non_ascii(self):
        s, u = "sécret", "https://example.com/é"
        m = b64(s.encode("utf-8"), (u + "k" + "ü").encode("utf-8"), hashlib.sha1)
        self.assertTrue(T.verify_twilio("k=ü".encode("utf-8"), s, m, url=u)[0])

    def test_json_body_hash(self):
        url = self.URL + "?bodySHA256=" + hashlib.sha256(BODY).hexdigest().upper()
        m = b64(SECRET.encode(), url.encode(), hashlib.sha1)
        ok, notes = T.verify_twilio(BODY, SECRET, m, url=url)
        self.assertTrue(ok)
        self.assertEqual(notes, ["computed " + m,
                                 "bodySHA256 matches (computed %s)" % hashlib.sha256(BODY).hexdigest()])
        ok, notes = T.verify_twilio(b'{"a":2}', SECRET, m, url=url)
        self.assertFalse(ok)
        self.assertEqual(notes[0], "computed " + m)
        self.assertEqual(notes[1], "bodySHA256 DOES NOT match (computed %s)" % hashlib.sha256(b'{"a":2}').hexdigest())


class Generic(unittest.TestCase):
    def test_hex_and_base64_notes(self):
        k = SECRET.encode()
        for mod, name in ((hashlib.sha256, "sha256"), (hashlib.sha1, "sha1"), (hashlib.sha512, "sha512")):
            e = hx(k, BODY, mod)
            self.assertEqual(T.verify_generic(BODY, SECRET, e.upper(), digestmod=mod), (True, ["computed %s=%s" % (name, e)]))
            e64 = b64(k, BODY, mod)
            self.assertEqual(T.verify_generic(BODY, SECRET, e64, digestmod=mod, encoding="base64"),
                             (True, ["computed %s=%s" % (name, e64)]))
        # defaults: sha256 + hex
        e = hx(k, BODY)
        self.assertEqual(T.verify_generic(BODY, SECRET, " " + e + " "), (True, ["computed sha256=" + e]))
        self.assertFalse(T.verify_generic(BODY, SECRET, b64(k, BODY))[0])
        self.assertFalse(T.verify_generic(BODY, SECRET, e, encoding="base64")[0])

    def test_non_ascii_secret(self):
        s = "sécret"
        self.assertTrue(T.verify_generic(BODY, s, hx(s.encode("utf-8"), BODY))[0])


class Ed25519(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.pub = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.msg = b"hello ed25519"
        self.sig = self.priv.sign(self.msg)

    def test_valid_and_length_checks(self):
        self.assertTrue(T.ed25519_verify(self.pub, self.msg, self.sig))
        self.assertFalse(T.ed25519_verify(self.pub, self.msg + b"!", self.sig))
        self.assertFalse(T.ed25519_verify(self.pub[:-1], self.msg, self.sig))
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, self.sig[:-1]))
        self.assertFalse(T.ed25519_verify(self.pub + b"\0", self.msg, self.sig))
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, self.sig + b"\0"))
        self.assertFalse(T.ed25519_verify(b"", self.msg, b""))
        self.assertFalse(T.ed25519_verify(self.pub[:-1], self.msg, self.sig + b"\0"))   # one length wrong, one too long
        self.assertFalse(T.ed25519_verify(self.pub + b"\0", self.msg, self.sig[:-1]))

    def test_s_range(self):
        s = int.from_bytes(self.sig[32:], "little")
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, self.sig[:32] + (s + T._Q).to_bytes(32, "little")))
        # s == _Q is out of range too (and s - _Q + _Q == s would otherwise be accepted)
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, self.sig[:32] + T._Q.to_bytes(32, "little")))

    def test_bad_points(self):
        bad = (T._P).to_bytes(32, "little")                 # y == p is not canonical
        self.assertFalse(T.ed25519_verify(bad, self.msg, self.sig))
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, bad + self.sig[32:]))
        self.assertFalse(T.ed25519_verify(self.pub, self.msg, (2).to_bytes(32, "little") + self.sig[32:]))

    def test_recover_x(self):
        self.assertIsNone(T._recover_x(T._P, 0))
        self.assertIsNone(T._recover_x(T._P + 1, 0))
        self.assertEqual(T._recover_x(1, 0), 0)             # y == 1: x == 0
        self.assertIsNone(T._recover_x(1, 1))               # ... and there is no odd root
        self.assertEqual(T._recover_x(T._GY, 0), T._GX)
        self.assertEqual(T._recover_x(T._GY, 1), T._P - T._GX)
        self.assertEqual(T._recover_x(T._GY, 0) & 1, 0)
        self.assertIsNone(T._recover_x(2, 0))               # not on the curve
        # the base point's x is even (sign 0); the other root is odd
        x1 = T._recover_x(T._GY, 1)
        self.assertEqual(x1 & 1, 1)
        for y in (3, 5, 7, 11, 13, 17, 19, 23):
            for sign in (0, 1):
                x = T._recover_x(y, sign)
                if x is not None:
                    self.assertEqual(x & 1, sign)
                    self.assertEqual((x * x * (T._D * y * y + 1) - (y * y - 1)) % T._P, 0)
        # a y whose x^2 candidate needs the sqrt(-1) correction
        found = False
        for y in range(2, 200):
            x2 = (y * y - 1) * pow(T._D * y * y + 1, T._P - 2, T._P)
            r = pow(x2, (T._P + 3) // 8, T._P)
            if (r * r - x2) % T._P and (r * r * -1 - x2) % T._P == 0 or ((r * r - x2) % T._P and pow(r * T._SQRT_M1, 2, T._P) == x2 % T._P):
                x = T._recover_x(y, 0)
                self.assertIsNotNone(x)
                self.assertEqual((x * x - x2) % T._P, 0)
                found = True
                break
        self.assertTrue(found)

    def test_equal(self):
        G = T._G
        k = 7
        scaled = tuple(c * k % T._P for c in G)
        self.assertTrue(T._equal(G, scaled))
        self.assertTrue(T._equal(G, G))
        other = T._mul(2, G)
        self.assertFalse(T._equal(G, other))
        # same x, different y
        a = (G[0], G[1], 1, G[3])
        b = (G[0], (G[1] + 1) % T._P, 1, G[3])
        self.assertFalse(T._equal(a, b))
        # same y, different x
        c = ((G[0] + 1) % T._P, G[1], 1, G[3])
        self.assertFalse(T._equal(a, c))
        # scaled Z in the other operand too, with distinct non-trivial Zs
        s2 = tuple(c2 * 5 % T._P for c2 in G)
        self.assertTrue(T._equal(scaled, s2))
        self.assertTrue(T._equal(s2, scaled))
        self.assertFalse(T._equal(scaled, tuple(c2 * 5 % T._P for c2 in other)))


class StandardWebhooks(unittest.TestCase):
    KEY = b"0123456789abcdef0123456789abcdef"
    SEC = "whsec_" + base64.b64encode(KEY).decode()
    WID = "msg_1"

    def signed(self, ts=NOW, body=BODY, wid=None):
        return ("%s.%s." % (wid or self.WID, ts)).encode() + body

    def mac(self, ts=NOW, key=None):
        return b64(key or self.KEY, self.signed(ts))

    def call(self, sig, secret=None, ts=str(NOW), wid=None, **kw):
        wid = self.WID if wid is None else wid
        with mock.patch.object(T.time, "time", return_value=float(NOW)):
            return T.verify_standard_webhooks(BODY, secret or self.SEC, sig, timestamp=ts, webhook_id=wid, **kw)

    def test_requirements(self):
        msg = "standard-webhooks requires --webhook-id and --timestamp (webhook-id / webhook-timestamp headers)"
        self.assertEqual(T.verify_standard_webhooks(BODY, self.SEC, "v1,x"), (False, [msg]))
        self.assertEqual(T.verify_standard_webhooks(BODY, self.SEC, "v1,x", timestamp="1"), (False, [msg]))
        self.assertEqual(T.verify_standard_webhooks(BODY, self.SEC, "v1,x", webhook_id="w"), (False, [msg]))
        self.assertEqual(T.verify_standard_webhooks(BODY, self.SEC, "v1,x", timestamp="", webhook_id="w"), (False, [msg]))
        self.assertEqual(T.verify_standard_webhooks(BODY, self.SEC, "v1,x", timestamp="1", webhook_id=""), (False, [msg]))

    def test_malformed(self):
        msg = "malformed signature: expected 'v1,<base64>' or 'v1a,<base64>' (space-separated)"
        self.assertEqual(self.call("nocomma"), (False, [msg]))
        self.assertEqual(self.call(""), (False, [msg]))

    def test_v1_valid_notes(self):
        m = self.mac()
        self.assertEqual(self.call("v1," + m), (True, ["computed v1," + m]))
        self.assertEqual(self.call("v1,AAAA v1," + m), (True, ["computed v1," + m]))
        self.assertEqual(self.call("v2," + m), (False, ["computed v1," + m]))
        self.assertEqual(self.call("v1a," + m), (False, ["computed v1," + m]))
        self.assertFalse(self.call("v1,AAAA")[0])
        self.assertFalse(self.call("v1," + m, wid="msg_2")[0])
        self.assertFalse(self.call("v1," + m, ts=str(NOW + 1))[0])

    def test_signature_value_may_contain_commas(self):
        m = self.mac()
        ok, notes = self.call("v1,%s,extra" % m)
        self.assertFalse(ok)          # split only on the first comma: the value is not the bare MAC
        ok, notes = self.call("v1,x,y")
        self.assertFalse(ok)
        self.assertEqual(notes[0], "computed v1," + m)

    def test_secret_parsing(self):
        raw = base64.b64encode(self.KEY).decode()
        m = self.mac()
        self.assertEqual(self.call("v1," + m, secret=raw), (True, ["computed v1," + m]))      # bare base64 key
        # whsec_ prefix removed only at the first underscore
        k2 = b"\xfb\xff\xbe" * 4
        self.assertEqual(self.call("v1," + b64(k2, self.signed()), secret="whsec_" + base64.b64encode(k2).decode())[0], True)
        # a bare key with an underscore-free base64 alphabet but whpk_/whsec_ lookalike
        self.assertEqual(self.call("v1," + m, secret="whsec_" + raw + "_" )[0], False)
        msg = "secret is not base64 (expected whsec_<base64> or whpk_<base64>)"
        self.assertEqual(self.call("v1," + m, secret="whsec_!!!!"), (False, [msg]))
        self.assertEqual(self.call("v1," + m, secret="whsec_QU*JD"), (False, [msg]))   # junk is not skipped
        self.assertEqual(self.call("v1," + m, secret="plain*key"), (False, [msg]))
        self.assertEqual(self.call("v1," + m, secret="whpk_QU*JD"), (False, [msg]))

    def test_replay_warning(self):
        m = self.mac(ts=NOW - 1000)
        with mock.patch.object(T.time, "time", return_value=float(NOW)):
            ok, notes = T.verify_standard_webhooks(BODY, self.SEC, "v1," + m, timestamp=str(NOW - 1000), webhook_id=self.WID)
        self.assertTrue(ok)
        self.assertEqual(notes, ["computed v1," + m,
                                 "WARNING: timestamp is 1000s from now (tolerance 300s) -- "
                                 "the Standard Webhooks libraries would reject this as a possible replay"])

    def test_unicode_ids_and_secret_bytes(self):
        wid = "msg_é"
        m = b64(self.KEY, ("%s.%s." % (wid, NOW)).encode("utf-8") + BODY)
        self.assertTrue(self.call("v1," + m, wid=wid)[0])

    def ed(self):
        priv = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return priv, "whpk_" + base64.b64encode(pub).decode()

    def test_ed25519(self):
        priv, pk = self.ed()
        sig = base64.b64encode(priv.sign(self.signed())).decode()
        self.assertEqual(self.call("v1a," + sig, secret=pk), (True, ["Ed25519 (v1a) signature verified"]))
        self.assertEqual(self.call("v1a,AAAA v1a," + sig, secret=pk), (True, ["Ed25519 (v1a) signature verified"]))
        bad = base64.b64encode(priv.sign(b"other")).decode()
        self.assertEqual(self.call("v1a," + bad, secret=pk), (False, ["Ed25519 (v1a) signature does not verify"]))
        # a v1 signature alone is not a v1a signature: explained in a second note
        self.assertEqual(self.call("v1," + sig, secret=pk),
                         (False, ["Ed25519 (v1a) signature does not verify",
                                  "no v1a signature in the header (a whpk_ key verifies Ed25519 v1a signatures)"]))
        # junk base64 in one v1a entry does not hide a good one, and does not raise
        self.assertEqual(self.call("v1a,QU*JD v1a," + sig, secret=pk)[0], True)
        self.assertEqual(self.call("v1a,QU*JD", secret=pk), (False, ["Ed25519 (v1a) signature does not verify"]))
        # the result is a real bool
        self.assertIs(self.call("v1a," + bad, secret=pk)[0], False)
        self.assertIs(self.call("v1a," + sig, secret=pk)[0], True)

    def test_v1_result_is_bool(self):
        self.assertIs(self.call("v1," + self.mac())[0], True)
        self.assertIs(self.call("v1,AAAA")[0], False)


class Main(unittest.TestCase):
    def args(self, scheme, sig, *extra, payload="x"):
        return ["--scheme", scheme, "--secret", SECRET, "--signature", sig, "--payload", payload] + list(extra)

    def test_valid_plain_output_and_exit_codes(self):
        e = hx(SECRET.encode(), b"x")
        rc, out, err = cli(self.args("github", "sha256=" + e))
        self.assertEqual((rc, out, err), (0, "VALID: computed sha256=%s\n" % e, ""))
        rc, out, err = cli(self.args("github", "sha256=" + "0" * 64))
        self.assertEqual((rc, out, err), (1, "INVALID: computed sha256=%s\n" % e, ""))

    def test_notes_joined_with_semicolon(self):
        url = "https://e.com/p?bodySHA256=" + "0" * 64
        rc, out, _ = cli(self.args("twilio", "AAAA", "--url", url))
        self.assertEqual(rc, 1)
        self.assertRegex(out, r"^INVALID: computed \S+; bodySHA256 DOES NOT match \(computed [0-9a-f]{64}\)\n$")

    def test_json_exact(self):
        e = hx(SECRET.encode(), b"x")
        rc, out, _ = cli(self.args("github", "sha256=" + e, "--json"))
        self.assertEqual(rc, 0)
        self.assertEqual(out, json.dumps({"schema_version": 1, "tool": "webhook-sig-verifier", "version": T.__version__,
                                          "exit_code": 0, "scheme": "github", "valid": True,
                                          "notes": ["computed sha256=" + e], "warnings": [],
                                          "payload_bytes": 1}, indent=2) + "\n")
        rc, out, _ = cli(self.args("stripe", "t=1,v1=" + "0" * 64, "--json"))
        d = json.loads(out)
        self.assertEqual((rc, d["exit_code"], d["valid"]), (1, 1, False))
        self.assertEqual(len(d["notes"]), 1)
        self.assertEqual(len(d["warnings"]), 1)
        self.assertTrue(d["warnings"][0].startswith("WARNING: timestamp is "))
        self.assertFalse(d["notes"][0].startswith("WARNING"))

    def test_quiet_and_json_precedence(self):
        e = hx(SECRET.encode(), b"x")
        for flag in ("-q", "--quiet"):
            self.assertEqual(cli(self.args("github", "sha256=" + e, flag)), (0, "", ""))
            self.assertEqual(cli(self.args("github", "sha256=0", flag)), (1, "", ""))
            self.assertEqual(cli(self.args("github", "sha256=0", flag, "--json")), (1, "", ""))

    def test_usage_errors_exit_2(self):
        cases = [
            (self.args("slack", "v0=a"), "--scheme slack requires --timestamp (the request timestamp header)"),
            (self.args("zoom", "v0=a"), "--scheme zoom requires --timestamp (the request timestamp header)"),
            (self.args("standard-webhooks", "v1,a"), "--scheme standard-webhooks requires --webhook-id and --timestamp"),
            (self.args("standard-webhooks", "v1,a", "--timestamp", "1"), "--scheme standard-webhooks requires --webhook-id and --timestamp"),
            (self.args("standard-webhooks", "v1,a", "--webhook-id", "w"), "--scheme standard-webhooks requires --webhook-id and --timestamp"),
            (self.args("square", "a"), "--scheme square requires --url (the URL the provider signed)"),
            (self.args("twilio", "a"), "--scheme twilio requires --url (the URL the provider signed)"),
            (self.args("github", "a", "--payload-file", "/dev/null"), "use either --payload or --payload-file, not both"),
            (self.args("github", "a", "--payload-file", "/nonexistent/zz", payload="")[:6] + ["--payload-file", "/nonexistent/zz"],
             "can't read --payload-file: [Errno 2] No such file or directory: '/nonexistent/zz'"),
        ]
        for argv, msg in cases:
            rc, out, err = cli(argv)
            self.assertEqual(rc, 2, argv)
            self.assertEqual(out, "")
            self.assertTrue(err.startswith("usage: webhook-sig-verifier"), err)
            self.assertIn("webhook-sig-verifier: error: " + msg + "\n", err)

    def test_required_args_and_bad_choices(self):
        rc, _, err = cli([])
        self.assertEqual(rc, 2)
        self.assertIn("the following arguments are required: --scheme, --secret, --signature", err)
        rc, _, err = cli(["--scheme", "nope", "--secret", "a", "--signature", "b"])
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice: 'nope'", err)
        for s in T.SCHEMES:
            self.assertIn(s, err)
        rc, _, err = cli(["--scheme", "github", "--secret", "a", "--signature", "b", "--encoding", "zz"])
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice: 'zz' (choose from", err)
        rc, _, err = cli(["--scheme", "github", "--secret", "a", "--signature", "b", "--tolerance", "x"])
        self.assertEqual(rc, 2)
        self.assertIn("argument --tolerance: invalid int value: 'x'", err)

    def test_payload_sources(self):
        e = hx(SECRET.encode(), "é".encode("utf-8"))
        self.assertEqual(cli(self.args("github", "sha256=" + e, payload="é"))[0], 0)   # --payload is UTF-8
        e = hx(SECRET.encode(), b"")
        self.assertEqual(cli(self.args("github", "sha256=" + e, payload=""))[0], 0)    # empty --payload is a payload
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\xff\x00file")
        try:
            e = hx(SECRET.encode(), b"\xff\x00file")
            argv = ["--scheme", "github", "--secret", SECRET, "--signature", "sha256=" + e, "--payload-file", f.name]
            self.assertEqual(cli(argv)[0], 0)
            argv2 = ["--scheme", "github", "--secret", SECRET, "--signature", "sha256=" + e]
            self.assertEqual(cli(argv2, stdin=b"\xff\x00file")[0], 0)          # stdin when neither is given
            rc, out, _ = cli(argv + ["--json"])
            self.assertEqual(json.loads(out)["payload_bytes"], 6)
        finally:
            os.unlink(f.name)

    def test_tolerance_option_reaches_the_verifier(self):
        e = hx(SECRET.encode(), b"v0:1000:x")
        with mock.patch.object(T.time, "time", return_value=1500.0):
            rc, out, _ = cli(self.args("slack", "v0=" + e, "--timestamp", "1000"))
            self.assertIn("WARNING: timestamp is 500s from now (tolerance 300s)", out)
            rc, out, _ = cli(self.args("slack", "v0=" + e, "--timestamp", "1000", "--tolerance", "500"))
            self.assertNotIn("WARNING", out)
            rc, out, _ = cli(self.args("zoom", "v0=" + e, "--timestamp", "1000", "--tolerance", "10"))
            self.assertIn("(tolerance 10s)", out)

    def test_every_scheme_dispatches_with_its_own_options(self):
        k = SECRET.encode()
        wid, ts = "m1", "1700000000"
        with mock.patch.object(T.time, "time", return_value=1700000000.0):
            cases = [
                ("stripe", "t=%s,v1=%s" % (ts, hx(k, ("%s." % ts).encode() + b"x")), []),
                ("slack", "v0=" + hx(k, b"v0:%s:x" % ts.encode()), ["--timestamp", ts]),
                ("zoom", "v0=" + hx(k, b"v0:%s:x" % ts.encode()), ["--timestamp", ts]),
                ("shopify", b64(k, b"x"), []),
                ("square", b64(k, b"https://u/x"), ["--url", "https://u/"]),
                ("twilio", b64(k, b"https://u/?a=1x", hashlib.sha1), ["--url", "https://u/?a=1"]),
                ("generic-sha1", hx(k, b"x", hashlib.sha1), []),
                ("generic-sha256", hx(k, b"x"), []),
                ("generic-sha512", hx(k, b"x", hashlib.sha512), []),
                ("generic-sha256", b64(k, b"x"), ["--encoding", "base64"]),
            ]
            for scheme, sig, extra in cases:
                rc, out, _ = cli(self.args(scheme, sig, *extra))
                self.assertEqual(rc, 0, (scheme, out))
            sk = base64.b64encode(b"k" * 16).decode()
            sig = "v1," + b64(b"k" * 16, ("%s.%s." % (wid, ts)).encode() + b"x")
            rc, out, _ = cli(["--scheme", "standard-webhooks", "--secret", "whsec_" + sk, "--signature", sig,
                              "--payload", "x", "--webhook-id", wid, "--timestamp", ts])
            self.assertEqual(rc, 0, out)

    def test_runtime_error_is_exit_3(self):
        with mock.patch.object(T, "read_payload", side_effect=RuntimeError("boom")):
            rc, out, err = cli(self.args("github", "a"))
        self.assertEqual((rc, out, err), (3, "", "webhook-sig-verifier: error: RuntimeError: boom\n"))

    def test_main_passes_argv_through(self):
        self.assertEqual(cli(self.args("github", "sha256=0"))[0], 1)
        with mock.patch.object(T.sys, "argv", ["webhook-sig-verifier"] + self.args("github", "sha256=0")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(T.main(), 1)
            self.assertTrue(out.getvalue().startswith("INVALID: "))

    def test_version(self):
        rc, out, _ = cli(["--version"])
        self.assertEqual((rc, out), (0, "webhook-sig-verifier %s\n" % T.__version__))

    def test_help_text(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "100"}):
            rc, out, _ = cli(["--help"])
        self.assertEqual(rc, 0)
        h = re.sub(r"\s+", " ", out)
        self.assertTrue(h.startswith("usage: webhook-sig-verifier [-h] [--version] --scheme"))
        self.assertIn(re.sub(r"\s+", " ", T.__doc__.strip()), h)       # the module doc is the description
        for frag in (
            "Which provider's signature scheme to check",
            "The webhook signing secret (standard-webhooks: whsec_... or an Ed25519 whpk_... public key)",
            "The received signature header value",
            "Raw payload as a string (use --payload-file for exact bytes)",
            "Path to a file containing the exact raw request body",
            "slack/zoom/standard-webhooks: the request timestamp header",
            "standard-webhooks: the webhook-id header",
            "square/twilio: the exact notification URL that was signed",
            "generic-*: how the signature is encoded (default hex)",
            "Replay tolerance in seconds (default 300, the providers' default)",
            "machine-readable JSON result",
            "print nothing on stdout; the exit code (and errors on stderr) are the result",
        ):
            self.assertIn(frag, h)
        for opt in ("--scheme", "--secret", "--signature", "--payload", "--payload-file", "--timestamp", "--webhook-id",
                    "--url", "--encoding", "--tolerance", "--json", "-q, --quiet"):
            self.assertIn(opt, h)
        self.assertIn("{hex,base64}", h)
        self.assertEqual(T.SCHEMES.count("zoom"), 1)


if __name__ == "__main__":
    unittest.main()
