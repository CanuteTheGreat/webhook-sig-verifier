# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.0 - 2026-10-16

- New schemes: **Standard Webhooks** (Svix and others: `v1,` HMAC-SHA256 with `whsec_` secrets and `v1a,`
  Ed25519 with `whpk_` public keys, verified by a pure-Python RFC 8032 implementation), **Shopify**,
  **Square**, **Twilio** (form and JSON/bodySHA256 requests) and **Zoom**.
- Generic HMAC accepts base64 signatures (`--encoding base64`) and SHA-512.
- `--json` output.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/webhook-sig-verifier.git`
  puts a `webhook-sig-verifier` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Accept every v1= in a Stripe header (secret roll), case-insensitive hex, usage errors exit 2; add CI tests against the official Stripe/Slack SDKs
- Add MIT LICENSE file

## 1.0.0 - 2026-09-30

- First public release.
