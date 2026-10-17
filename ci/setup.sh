#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
pip install -q --disable-pip-version-check --root-user-action=ignore stripe slack_sdk twilio cryptography
# The official Standard Webhooks library needs Python >= 3.9; older legs use its published test vector.
if python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  pip install -q --disable-pip-version-check --root-user-action=ignore standardwebhooks
fi
python -c "import stripe, slack_sdk, twilio, cryptography; print('stripe', stripe.VERSION, 'slack_sdk', slack_sdk.version.__version__, 'twilio', twilio.__version__, 'cryptography', cryptography.__version__)"
