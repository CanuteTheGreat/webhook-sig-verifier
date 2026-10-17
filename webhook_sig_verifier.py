#!/usr/bin/env python3
"""
webhook-sig-verifier -- verify webhook signatures locally, without external calls.

Supports the signature schemes used by GitHub, Stripe, Slack, Zoom, Shopify,
Square, Twilio, Standard Webhooks (Svix and the other providers that follow
standardwebhooks.com, HMAC-SHA256 and Ed25519) and generic HMAC in hex or
base64, so you can paste a payload + secret + received signature and find out
whether it *should* validate, without touching production code or making any
network request.

Zero dependencies beyond the Python standard library (Ed25519 is verified
with a pure-Python RFC 8032 implementation). No data leaves your machine.

Usage:
    webhook-sig-verifier --scheme github --secret "mysecret" \\
        --payload-file payload.json --signature "sha256=abcdef..."

    webhook-sig-verifier --scheme stripe --secret "whsec_..." \\
        --payload-file payload.json --signature "t=1699999999,v1=abcdef..."

    webhook-sig-verifier --scheme slack --secret "signingsecret" \\
        --payload-file payload.json --signature "v0=abcdef..." --timestamp 1699999999

    webhook-sig-verifier --scheme standard-webhooks --secret "whsec_..." \\
        --webhook-id msg_2Lj... --timestamp 1699999999 \\
        --payload-file payload.json --signature "v1,K5oZfz..."

    webhook-sig-verifier --scheme shopify --secret "shpss_..." \\
        --payload-file payload.json --signature "X-Shopify-Hmac-Sha256 value (base64)"

    webhook-sig-verifier --scheme twilio --secret "<auth token>" \\
        --url "https://example.com/sms" --payload "From=%2B1555&Body=hi" --signature "<X-Twilio-Signature>"

    webhook-sig-verifier --scheme generic-sha256 --encoding base64 \\
        --secret "mysecret" --payload-file payload.json --signature "q1MK..."

With neither --payload nor --payload-file, the payload is read from stdin.

Exit code 0 = signature valid, 1 = invalid, 2 = usage error.
"""
__version__ = "1.2.0"

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time
import urllib.parse

SCHEMES = ["github", "stripe", "slack", "zoom", "shopify", "square", "twilio", "standard-webhooks",
           "generic-sha256", "generic-sha1", "generic-sha512"]


def read_payload(args) -> bytes:
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            return f.read()
    if args.payload is not None:
        return args.payload.encode("utf-8")
    return sys.stdin.buffer.read()


def _age_warning(ts, tolerance, who):
    try:
        age = abs(time.time() - int(ts))
    except (TypeError, ValueError):
        return "WARNING: timestamp is not a valid integer"
    if age > tolerance:
        return (f"WARNING: timestamp is {int(age)}s from now (tolerance {tolerance}s) "
                f"-- {who} would reject this as a possible replay")
    return None


def _b64eq(expected: bytes, received: str) -> bool:
    try:
        got = base64.b64decode(received.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    return hmac.compare_digest(expected, got)


def verify_github(payload, secret, signature, **_):
    """GitHub sends 'sha256=<hexdigest>' (or legacy 'sha1=<hexdigest>')."""
    if "=" not in signature:
        return False, ["malformed signature: expected 'sha256=<hex>' or 'sha1=<hex>'"]
    algo, _, sig_hex = signature.partition("=")
    if algo not in ("sha256", "sha1"):
        return False, [f"unsupported algo '{algo}' (GitHub uses sha256, legacy sha1)"]
    digestmod = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    expected = hmac.new(secret.encode("utf-8"), payload, digestmod).hexdigest()
    return hmac.compare_digest(expected, sig_hex.strip().lower()), [f"computed {algo}={expected}"]


def verify_stripe(payload, secret, signature, tolerance=300, **_):
    """Stripe sends 'Stripe-Signature: t=<ts>,v1=<hex>[,v0=<hex>]': HMAC-SHA256 over '<t>.<payload>'.
    During a secret roll several v1= values arrive in one header; any match is valid."""
    pairs = [p.strip().split("=", 1) for p in signature.split(",") if "=" in p]
    ts = next((v for k, v in pairs if k == "t"), None)
    v1s = [v.strip().lower() for k, v in pairs if k == "v1"]
    if not ts or not v1s:
        return False, ["malformed signature: expected 't=...,v1=...'"]
    expected = hmac.new(secret.encode("utf-8"), f"{ts}.".encode("utf-8") + payload, hashlib.sha256).hexdigest()
    notes = [f"computed v1={expected}"]
    w = _age_warning(ts, tolerance, "Stripe's own libraries")
    if w:
        notes.append(w)
    return any(hmac.compare_digest(expected, v1) for v1 in v1s), notes


def _v0_scheme(payload, secret, signature, timestamp, tolerance, who):
    if not timestamp:
        return False, [f"{who} scheme requires --timestamp"]
    if not signature.startswith("v0="):
        return False, ["malformed signature: expected 'v0=<hex>'"]
    base = f"v0:{timestamp}:".encode("utf-8") + payload
    expected = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    notes = [f"computed {expected}"]
    w = _age_warning(timestamp, tolerance, f"{who}'s guidance")
    if w:
        notes.append(w)
    return hmac.compare_digest(expected, signature.strip().lower()), notes


def verify_slack(payload, secret, signature, timestamp=None, tolerance=300, **_):
    """Slack: 'X-Slack-Signature: v0=<hex>' over 'v0:<X-Slack-Request-Timestamp>:<body>'."""
    return _v0_scheme(payload, secret, signature, timestamp, tolerance, "Slack")


def verify_zoom(payload, secret, signature, timestamp=None, tolerance=300, **_):
    """Zoom: 'x-zm-signature: v0=<hex>' over 'v0:<x-zm-request-timestamp>:<body>' with the secret token."""
    return _v0_scheme(payload, secret, signature, timestamp, tolerance, "Zoom")


def verify_shopify(payload, secret, signature, **_):
    """Shopify: 'X-Shopify-Hmac-Sha256: base64(HMAC-SHA256(client secret, raw body))'."""
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return _b64eq(mac, signature), ["computed " + base64.b64encode(mac).decode()]


def verify_square(payload, secret, signature, url=None, **_):
    """Square: 'x-square-hmacsha256-signature: base64(HMAC-SHA256(key, notification URL + body))'."""
    if not url:
        return False, ["square scheme requires --url (the notification URL configured in Square)"]
    mac = hmac.new(secret.encode("utf-8"), url.encode("utf-8") + payload, hashlib.sha256).digest()
    return _b64eq(mac, signature), ["computed " + base64.b64encode(mac).decode()]


def verify_twilio(payload, secret, signature, url=None, **_):
    """Twilio: 'X-Twilio-Signature: base64(HMAC-SHA1(auth token, URL + sorted POST params as key+value))'.
    For JSON bodies Twilio signs only the URL, which then carries bodySHA256=<hex sha256 of the body>."""
    if not url:
        return False, ["twilio scheme requires --url (the full URL Twilio requested, including any query string)"]
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    notes = []
    if "bodySHA256" in query:
        data = url
        body_hash = hashlib.sha256(payload).hexdigest()
        body_ok = hmac.compare_digest(body_hash, query["bodySHA256"][0].lower())
        notes.append("bodySHA256 %s (computed %s)" % ("matches" if body_ok else "DOES NOT match", body_hash))
    else:
        body_ok = True
        params = urllib.parse.parse_qsl(payload.decode("utf-8", "replace"), keep_blank_values=True)
        data = url + "".join(k + v for k, v in sorted(params))
    mac = hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).digest()
    notes.insert(0, "computed " + base64.b64encode(mac).decode())
    return _b64eq(mac, signature) and body_ok, notes


# ---------------------------------------------------------------- Ed25519 (RFC 8032 section 6, verify only)

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


def verify_standard_webhooks(payload, secret, signature, timestamp=None, webhook_id=None, tolerance=300, **_):
    """Standard Webhooks (standardwebhooks.com, used by Svix and others): signed content is
    '<webhook-id>.<webhook-timestamp>.<body>'. 'webhook-signature' is a space-separated list of
    'v1,<base64 HMAC-SHA256>' (secret 'whsec_<base64 key>') or 'v1a,<base64 Ed25519>' (public key
    'whpk_<base64>'); any one matching is valid."""
    if not webhook_id or not timestamp:
        return False, ["standard-webhooks requires --webhook-id and --timestamp (webhook-id / webhook-timestamp headers)"]
    signed = f"{webhook_id}.{timestamp}.".encode("utf-8") + payload
    sigs = [s.split(",", 1) for s in signature.split() if "," in s]
    if not sigs:
        return False, ["malformed signature: expected 'v1,<base64>' or 'v1a,<base64>' (space-separated)"]
    notes = []
    raw_key = secret.split("_", 1)[1] if secret.startswith(("whsec_", "whpk_")) else secret
    try:
        key = base64.b64decode(raw_key, validate=True)
    except (binascii.Error, ValueError):
        return False, ["secret is not base64 (expected whsec_<base64> or whpk_<base64>)"]
    ok = False
    if secret.startswith("whpk_"):
        for version, value in sigs:
            if version == "v1a":
                try:
                    ok = ok or ed25519_verify(key, signed, base64.b64decode(value, validate=True))
                except (binascii.Error, ValueError):
                    pass
        notes.append("Ed25519 (v1a) signature %s" % ("verified" if ok else "does not verify"))
        if not any(v == "v1a" for v, _ in sigs):
            notes.append("no v1a signature in the header (a whpk_ key verifies Ed25519 v1a signatures)")
    else:
        mac = hmac.new(key, signed, hashlib.sha256).digest()
        ok = any(v == "v1" and _b64eq(mac, value) for v, value in sigs)
        notes.append("computed v1," + base64.b64encode(mac).decode())
    w = _age_warning(timestamp, tolerance, "the Standard Webhooks libraries")
    if w:
        notes.append(w)
    return ok, notes


def verify_generic(payload, secret, signature, digestmod=hashlib.sha256, encoding="hex", **_):
    mac = hmac.new(secret.encode("utf-8"), payload, digestmod)
    name = mac.name.replace("hmac-", "")
    if encoding == "base64":
        return _b64eq(mac.digest(), signature), [f"computed {name}={base64.b64encode(mac.digest()).decode()}"]
    expected = mac.hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower()), [f"computed {name}={expected}"]


VERIFIERS = {
    "github": verify_github, "stripe": verify_stripe, "slack": verify_slack, "zoom": verify_zoom,
    "shopify": verify_shopify, "square": verify_square, "twilio": verify_twilio,
    "standard-webhooks": verify_standard_webhooks,
}


def main(argv=None):
    p = argparse.ArgumentParser(prog="webhook-sig-verifier", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    p.add_argument("--scheme", required=True, choices=SCHEMES, help="Which provider's signature scheme to check")
    p.add_argument("--secret", required=True,
                   help="The webhook signing secret (standard-webhooks: whsec_... or an Ed25519 whpk_... public key)")
    p.add_argument("--signature", required=True, help="The received signature header value")
    p.add_argument("--payload", help="Raw payload as a string (use --payload-file for exact bytes)")
    p.add_argument("--payload-file", help="Path to a file containing the exact raw request body")
    p.add_argument("--timestamp", help="slack/zoom/standard-webhooks: the request timestamp header")
    p.add_argument("--webhook-id", help="standard-webhooks: the webhook-id header")
    p.add_argument("--url", help="square/twilio: the exact notification URL that was signed")
    p.add_argument("--encoding", choices=["hex", "base64"], default="hex",
                   help="generic-*: how the signature is encoded (default hex)")
    p.add_argument("--tolerance", type=int, default=300,
                   help="Replay tolerance in seconds (default 300, the providers' default)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON result")
    args = p.parse_args(argv)
    if args.scheme in ("slack", "zoom") and not args.timestamp:
        p.error(f"--scheme {args.scheme} requires --timestamp (the request timestamp header)")
    if args.scheme == "standard-webhooks" and not (args.timestamp and args.webhook_id):
        p.error("--scheme standard-webhooks requires --webhook-id and --timestamp")
    if args.scheme in ("square", "twilio") and not args.url:
        p.error(f"--scheme {args.scheme} requires --url (the URL the provider signed)")
    if args.payload is not None and args.payload_file:
        p.error("use either --payload or --payload-file, not both")

    try:
        payload = read_payload(args)
    except OSError as e:
        p.error(f"can't read --payload-file: {e}")

    if args.scheme.startswith("generic-"):
        mod = {"generic-sha256": hashlib.sha256, "generic-sha1": hashlib.sha1, "generic-sha512": hashlib.sha512}[args.scheme]
        ok, notes = verify_generic(payload, args.secret, args.signature, digestmod=mod, encoding=args.encoding)
    else:
        ok, notes = VERIFIERS[args.scheme](payload, args.secret, args.signature, timestamp=args.timestamp,
                                           webhook_id=args.webhook_id, url=args.url, tolerance=args.tolerance)

    if args.json:
        print(json.dumps({"version": __version__, "scheme": args.scheme, "valid": ok,
                          "notes": [n for n in notes if not n.startswith("WARNING")],
                          "warnings": [n for n in notes if n.startswith("WARNING")],
                          "payload_bytes": len(payload)}, indent=2))
    else:
        print(("VALID" if ok else "INVALID") + ": " + "; ".join(notes))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
