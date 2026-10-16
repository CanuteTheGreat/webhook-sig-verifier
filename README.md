# webhook-sig-verifier

Verify webhook HMAC signatures locally, without touching production code or
making any network request. Paste your secret, payload, and the signature
header you received — find out immediately whether it *should* validate.

Supports the real, documented signature schemes for:

- **GitHub** — `X-Hub-Signature-256: sha256=<hex>` (or legacy `sha1=`)
- **Stripe** — `Stripe-Signature: t=<ts>,v1=<hex>` (also flags stale
  timestamps per Stripe's own replay-protection guidance)
- **Slack** — `X-Slack-Signature: v0=<hex>` + `X-Slack-Request-Timestamp`
  (also flags stale timestamps per Slack's own guidance)
- **Generic HMAC-SHA256 / HMAC-SHA1** — for anything else with a raw HMAC
  over the exact request body

Zero dependencies beyond the Python standard library. Nothing is sent
anywhere — it's pure local computation, so it's safe to run against real
production secrets on an air-gapped machine if you want to.

## Usage

```
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
```

Exit code `0` = valid, `1` = invalid (mismatched), `2` = usage error (e.g. Slack
without `--timestamp`, both `--payload` and `--payload-file`, unreadable file).

`--tolerance N` sets the replay window in seconds for the Stripe/Slack timestamp
warning (default 300, both providers' default). Stripe headers carrying several `v1=`
values (sent while you roll a signing secret) validate if any one matches. Python 3.8+.

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

## License

MIT — see LICENSE.
