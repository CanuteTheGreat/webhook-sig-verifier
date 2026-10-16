#!/usr/bin/env python3
"""
webhook-sig-verifier — verify webhook HMAC signatures without external calls.

Supports the signature schemes used by GitHub, Stripe, Slack, and a generic
raw-HMAC mode, so you can paste a payload + secret + received signature and
find out locally whether it *should* validate, without touching your
production code or making any network request.

Zero dependencies beyond the Python standard library. No data ever leaves
your machine — everything here is pure local computation.

Usage:
    python3 webhook_sig_verifier.py --scheme github \
        --secret "mysecret" \
        --payload-file payload.json \
        --signature "sha256=abcdef..."

    python3 webhook_sig_verifier.py --scheme stripe \
        --secret "whsec_..." \
        --payload-file payload.json \
        --signature "t=1699999999,v1=abcdef..."

    python3 webhook_sig_verifier.py --scheme slack \
        --secret "signingsecret" \
        --payload-file payload.json \
        --signature "v0=abcdef..." \
        --timestamp 1699999999

    python3 webhook_sig_verifier.py --scheme generic-sha256 \
        --secret "mysecret" \
        --payload-file payload.json \
        --signature "abcdef..."

With neither --payload nor --payload-file, the payload is read from stdin.

Exit code 0 = signature valid, 1 = invalid, 2 = usage error.
"""
import argparse
import hashlib
import hmac
import sys
import time


def read_payload(args) -> bytes:
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            return f.read()
    if args.payload is not None:
        return args.payload.encode("utf-8")
    return sys.stdin.buffer.read()


def verify_github(payload: bytes, secret: str, signature: str):
    """GitHub sends 'sha256=<hexdigest>' (or legacy 'sha1=<hexdigest>')."""
    if "=" not in signature:
        return False, "malformed signature: expected 'sha256=<hex>' or 'sha1=<hex>'"
    algo, _, sig_hex = signature.partition("=")
    if algo not in ("sha256", "sha1"):
        return False, f"unsupported algo '{algo}' (GitHub uses sha256, legacy sha1)"
    digestmod = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    mac = hmac.new(secret.encode("utf-8"), payload, digestmod)
    expected = mac.hexdigest()
    ok = hmac.compare_digest(expected, sig_hex.strip().lower())
    return ok, f"computed {algo}={expected}"


def verify_stripe(payload: bytes, secret: str, signature: str, tolerance: int = 300):
    """Stripe sends 'Stripe-Signature: t=<ts>,v1=<hex>[,v0=<hex>]'.
    Real check: HMAC-SHA256 over "<timestamp>.<payload>" using the webhook
    signing secret, compared against the v1 value(s). Also flags timestamp
    tolerance violations (Stripe recommends rejecting signatures where the
    timestamp is more than 5 minutes from now, to block replay attacks)."""
    # Keep every pair: during a secret roll Stripe sends several v1= values in one
    # header, and any one of them matching is a valid signature.
    pairs = [p.strip().split("=", 1) for p in signature.split(",") if "=" in p]
    ts = next((v for k, v in pairs if k == "t"), None)
    v1s = [v.strip().lower() for k, v in pairs if k == "v1"]
    if not ts or not v1s:
        return False, "malformed signature: expected 't=...,v1=...'"
    signed_payload = f"{ts}.".encode("utf-8") + payload
    mac = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256)
    expected = mac.hexdigest()
    matched = any(hmac.compare_digest(expected, v1) for v1 in v1s)
    notes = [f"computed v1={expected}"]
    try:
        age = abs(time.time() - int(ts))
        if age > tolerance:
            notes.append(
                f"WARNING: timestamp is {int(age)}s from now (tolerance {tolerance}s) "
                f"— Stripe's own libraries would reject this as a possible replay"
            )
    except ValueError:
        notes.append("WARNING: timestamp is not a valid integer")
    return matched, "; ".join(notes)


def verify_slack(payload: bytes, secret: str, signature: str, timestamp: str, tolerance: int = 300):
    """Slack sends 'X-Slack-Signature: v0=<hex>' plus 'X-Slack-Request-Timestamp'.
    Base string is 'v0:<timestamp>:<body>'."""
    if not timestamp:
        return False, "Slack scheme requires --timestamp (from X-Slack-Request-Timestamp header)"
    if not signature.startswith("v0="):
        return False, "malformed signature: expected 'v0=<hex>'"
    base = f"v0:{timestamp}:".encode("utf-8") + payload
    mac = hmac.new(secret.encode("utf-8"), base, hashlib.sha256)
    expected = f"v0={mac.hexdigest()}"
    ok = hmac.compare_digest(expected, signature.strip().lower())
    notes = [f"computed {expected}"]
    try:
        age = abs(time.time() - int(timestamp))
        if age > tolerance:
            notes.append(
                f"WARNING: timestamp is {int(age)}s from now (tolerance {tolerance}s) "
                f"— Slack's own guidance says reject anything over 5 minutes old"
            )
    except ValueError:
        notes.append("WARNING: timestamp is not a valid integer")
    return ok, "; ".join(notes)


def verify_generic(payload: bytes, secret: str, signature: str, digestmod):
    mac = hmac.new(secret.encode("utf-8"), payload, digestmod)
    expected = mac.hexdigest()
    ok = hmac.compare_digest(expected, signature.strip().lower())
    return ok, f"computed {digestmod().name}={expected}"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scheme", required=True,
                   choices=["github", "stripe", "slack", "generic-sha256", "generic-sha1"],
                   help="Which provider's signature scheme to check")
    p.add_argument("--secret", required=True, help="The webhook signing secret")
    p.add_argument("--signature", required=True, help="The received signature header value")
    p.add_argument("--payload", help="Raw payload as a string (use --payload-file for exact bytes)")
    p.add_argument("--payload-file", help="Path to a file containing the exact raw request body")
    p.add_argument("--timestamp", help="Required for --scheme slack (X-Slack-Request-Timestamp)")
    p.add_argument("--tolerance", type=int, default=300, help="Replay tolerance in seconds (default 300, Stripe/Slack default)")
    args = p.parse_args()
    if args.scheme == "slack" and not args.timestamp:
        p.error("--scheme slack requires --timestamp (the X-Slack-Request-Timestamp header)")
    if args.payload is not None and args.payload_file:
        p.error("use either --payload or --payload-file, not both")

    try:
        payload = read_payload(args)
    except OSError as e:
        p.error(f"can't read --payload-file: {e}")

    if args.scheme == "github":
        ok, note = verify_github(payload, args.secret, args.signature)
    elif args.scheme == "stripe":
        ok, note = verify_stripe(payload, args.secret, args.signature, args.tolerance)
    elif args.scheme == "slack":
        ok, note = verify_slack(payload, args.secret, args.signature, args.timestamp, args.tolerance)
    elif args.scheme == "generic-sha256":
        ok, note = verify_generic(payload, args.secret, args.signature, hashlib.sha256)
    elif args.scheme == "generic-sha1":
        ok, note = verify_generic(payload, args.secret, args.signature, hashlib.sha1)
    else:
        print("unknown scheme", file=sys.stderr)
        sys.exit(2)

    status = "VALID" if ok else "INVALID"
    print(f"{status}: {note}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
