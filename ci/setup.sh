#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
pip install -q --disable-pip-version-check --root-user-action=ignore stripe slack_sdk
python -c "import stripe, slack_sdk; print('stripe', stripe.VERSION, 'slack_sdk', slack_sdk.version.__version__)"
