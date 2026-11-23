"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors."""
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "webhook_sig_verifier.py")
sys.path.insert(0, ROOT)
import webhook_sig_verifier as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "webhook-sig-verifier")
SECRET = "contract-test-secret"
BODY = '{"event":"ping"}'
GOOD = hmac.new(SECRET.encode(), BODY.encode(), hashlib.sha256).hexdigest()
BAD = "0" * 64


def args(sig, *extra):
    return ("--scheme", "generic-sha256", "--secret", SECRET, "--payload", BODY, "--signature", sig) + extra


def cli(*a, **kw):
    return cs.run_cli(TOOL, a, **kw)


class TestExitCodes(unittest.TestCase):
    def test_valid_signature_is_0(self):
        self.assertEqual(cli(*args(GOOD))[0], 0)

    def test_invalid_signature_is_1(self):
        self.assertEqual(cli(*args(BAD))[0], 1)

    def test_payload_from_stdin(self):
        self.assertEqual(cli(*("--scheme", "generic-sha256", "--secret", SECRET, "--signature", GOOD), stdin=BODY)[0], 0)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for a in ((), ("--no-such-flag",), ("--scheme", "bogus", "--secret", "s", "--signature", "x"),
                  ("--scheme", "slack", "--secret", "s", "--signature", "x", "--payload", "p"),
                  args(GOOD, "--payload-file", "x")):
            rc, out, err = cli(*a)
            self.assertEqual(rc, 2, a)
            self.assertEqual(out, "", a)
            self.assertIn("usage:", err)

    def test_missing_payload_file_is_2(self):
        missing = os.path.join(tempfile.gettempdir(), "no-such-webhook-payload.bin")
        rc, out, err = cli("--scheme", "generic-sha256", "--secret", SECRET, "--signature", GOOD,
                           "--payload-file", missing)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("can't read --payload-file", err)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main(list(args(GOOD))), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())


class TestJson(unittest.TestCase):
    def check(self, sig, code):
        rc, out, err = cli(*args(sig, "--json"))
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["valid"], code == 0)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "webhook-sig-verifier")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        self.check(GOOD, 0)

    def test_findings(self):
        self.check(BAD, 1)

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"valid": True}, SCHEMA), [])
        good = {"schema_version": 1, "tool": "webhook-sig-verifier", "version": "1", "exit_code": 0, "scheme": "x",
                "valid": True, "notes": [], "warnings": [], "payload_bytes": 0}
        self.assertEqual(cs.validate(good, SCHEMA), [])
        self.assertNotEqual(cs.validate(dict(good, exit_code=9), SCHEMA), [])


class TestQuiet(unittest.TestCase):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for sig, code in ((GOOD, 0), (BAD, 1)):
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = cli(*args(sig, flag, *extra))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, sig))

    def test_without_quiet_the_report_is_printed(self):
        self.assertTrue(cli(*args(GOOD))[1].startswith("VALID"))
        self.assertTrue(cli(*args(BAD))[1].startswith("INVALID"))


if __name__ == "__main__":
    unittest.main()
