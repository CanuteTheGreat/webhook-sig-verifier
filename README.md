# webhook-sig-verifier

Verify webhook HMAC signatures locally, without touching production code or
making any network request. Paste your secret, payload, and the signature
header you received — find out immediately whether it *should* validate.

Supports the real, documented signature schemes for:

| `--scheme` | Header | Signature |
|---|---|---|
| `github` | `X-Hub-Signature-256` | `sha256=<hex>` HMAC of the body (legacy `sha1=`) |
| `stripe` | `Stripe-Signature` | `t=<ts>,v1=<hex>` over `<ts>.<body>`; several `v1=` (secret roll) accepted |
| `slack` | `X-Slack-Signature` + `X-Slack-Request-Timestamp` | `v0=<hex>` over `v0:<ts>:<body>` |
| `zoom` | `x-zm-signature` + `x-zm-request-timestamp` | `v0=<hex>` over `v0:<ts>:<body>` |
| `shopify` | `X-Shopify-Hmac-Sha256` | base64 HMAC-SHA256 of the body |
| `square` | `x-square-hmacsha256-signature` | base64 HMAC-SHA256 of notification URL + body (`--url`) |
| `twilio` | `X-Twilio-Signature` | base64 HMAC-SHA1 of URL + sorted form params, or URL with `bodySHA256=` for JSON (`--url`) |
| `standard-webhooks` | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `v1,<base64>` HMAC-SHA256 (`whsec_` secret) or `v1a,<base64>` Ed25519 (`whpk_` public key) over `<id>.<ts>.<body>` — Svix and every provider following standardwebhooks.com |
| `generic-sha256` / `generic-sha1` / `generic-sha512` | any | HMAC of the exact body, `--encoding hex` (default) or `base64` |

Stale timestamps (Stripe, Slack, Zoom, Standard Webhooks) are flagged per the providers'
replay-protection guidance (`--tolerance N`, default 300 s).

Zero dependencies beyond the Python standard library (Ed25519 is verified with a
pure-Python RFC 8032 implementation). Nothing is sent anywhere — it's pure local
computation, so it's safe to run against real production secrets on an air-gapped machine.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/webhook-sig-verifier.git        # latest release branch; puts `webhook-sig-verifier` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/webhook-sig-verifier.git@v1.2.0  # a pinned release
brew install canutethegreat/errant-tools/webhook-sig-verifier   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/webhook-sig-verifier                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.7+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/webhook_sig_verifier.py && python3 webhook_sig_verifier.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/webhook-sig-verifier/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install webhook-sig-verifier` doesn't work until it's published there.

## Usage

```
webhook-sig-verifier --scheme github --secret "mysecret" \
    --payload-file payload.json --signature "sha256=abcdef..."

webhook-sig-verifier --scheme stripe --secret "whsec_..." \
    --payload-file payload.json --signature "t=1699999999,v1=abcdef..."

webhook-sig-verifier --scheme slack --secret "signingsecret" \
    --payload-file payload.json --signature "v0=abcdef..." --timestamp 1699999999

webhook-sig-verifier --scheme standard-webhooks --secret "whsec_..." \
    --webhook-id msg_2Lj... --timestamp 1699999999 \
    --payload-file payload.json --signature "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4="

webhook-sig-verifier --scheme twilio --secret "<auth token>" \
    --url "https://example.com/sms" --payload "From=%2B15551234567&Body=hi" --signature "<X-Twilio-Signature>"

webhook-sig-verifier --scheme generic-sha256 --encoding base64 --json \
    --secret "mysecret" --payload-file payload.json --signature "q1MK..."
```

Exit code `0` = valid, `1` = invalid (mismatched), `2` = usage error (e.g. Slack
without `--timestamp`, Square/Twilio without `--url`, both `--payload` and
`--payload-file`, unreadable file). `--json` prints `{"valid", "scheme", "notes",
"warnings", "payload_bytes"}`. Python 3.7+.

Read the payload from a file with `--payload-file exact-body.json` to
guarantee byte-for-byte fidelity (whitespace/encoding differences are the
#1 cause of "my signature doesn't match" bugs) — or pipe it via stdin, or
pass `--payload` for quick manual testing.

## Why this exists

Debugging "my webhook signature doesn't validate" is almost always one of:
1. Wrong secret (rotated key, wrong environment)
2. Wrong base string (forgot the timestamp prefix for Stripe/Slack)
3. Payload re-serialized/re-encoded before hashing (whitespace changed)
4. Comparing against the wrong signature version (Stripe sends v0 *and* v1)

This tool isolates the HMAC computation from your actual server code so you
can rule steps 1–4 in or out in seconds, without redeploying anything.

Part of the [Errant Solutions](https://errant.solutions) spare-capacity
toolkit — free to use, pay-what-you-want if it saved you time:
https://errant.solutions

## Tests

`tests/` runs every scheme in Forgejo CI on Python 3.7 and current Python against the
providers' own code: the official `stripe`, `slack_sdk`, `twilio` and `standardwebhooks`
libraries, GitHub's and Standard Webhooks' published examples, and Ed25519 signatures made
with `cryptography`. CI then installs the package with pip and checks `--version`/`--help`.

## License

MIT — see LICENSE.
