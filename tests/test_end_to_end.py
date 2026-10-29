"""Generate a sample log, run the full CLI on it, and check against ground truth."""

import gzip
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from log_analyser.cli import main

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("generate_sample_log", ROOT / "scripts" / "generate_sample_log.py")
gen = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gen  # @dataclass needs the module registered before exec
_spec.loader.exec_module(gen)

START = datetime(2026, 10, 28)


def run_cli(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class GeneratorTests(unittest.TestCase):
    def test_deterministic_with_seed(self):
        self.assertEqual(gen.generate(START, seed=1)[0], gen.generate(START, seed=1)[0])
        self.assertNotEqual(gen.generate(START, seed=1)[0], gen.generate(START, seed=2)[0])

    def test_lines_are_chronological(self):
        text, _ = gen.generate(START, seed=3, iso=True)
        stamps = [line.split()[0] for line in text.splitlines()]
        self.assertEqual(stamps, sorted(stamps))


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log = Path(cls.tmp.name) / "auth.log"
        cls.log.write_text(gen.generate(START, seed=42)[0])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def analyse_json(self, *extra, path=None):
        code, out = run_cli(str(path or self.log), "--year", "2026", "--json", *extra)
        self.assertEqual(code, 0)
        return json.loads(out)

    def test_detects_injected_attacks_with_defaults(self):
        data = self.analyse_json()
        bf_ips = {b["ip"] for b in data["brute_force"]}
        self.assertEqual(bf_ips, {"203.0.113.45", "203.0.113.99"})  # fast attack + compromise

        [sus] = data["suspicious_logins"]
        self.assertEqual((sus["ip"], sus["user"], sus["severity"]), ("203.0.113.99", "deploy", "HIGH"))

        # No legitimate user (internal IPs) should be flagged
        for b in data["brute_force"]:
            self.assertFalse(b["ip"].startswith(("10.", "172.16.", "192.168.")))

    def test_slow_attack_caught_with_wider_window(self):
        data = self.analyse_json("--threshold", "10", "--window", "3600")
        self.assertIn("198.51.100.200", {b["ip"] for b in data["brute_force"]})

    def test_iso_format_gives_same_findings(self):
        iso = Path(self.tmp.name) / "auth_iso.log"
        iso.write_text(gen.generate(START, seed=42, iso=True)[0])
        a, b = self.analyse_json(), self.analyse_json(path=iso)
        self.assertEqual({x["ip"] for x in a["brute_force"]}, {x["ip"] for x in b["brute_force"]})
        self.assertEqual(len(a["successful_logins"]), len(b["successful_logins"]))

    def test_gzip_input(self):
        gz = Path(self.tmp.name) / "auth.log.1.gz"
        with gzip.open(gz, "wt") as f:
            f.write(self.log.read_text())
        self.assertEqual(self.analyse_json(path=gz), self.analyse_json())

    def test_text_report_sections(self):
        code, out = run_cli(str(self.log), "--year", "2026")
        self.assertEqual(code, 0)
        for heading in ("Overview", "Logins after repeated failures", "Brute-force attempts", "Successful logins"):
            self.assertIn(heading, out)
        self.assertIn("<-- suspicious", out)

    def test_missing_file_returns_error(self):
        code, _ = run_cli("/nonexistent/auth.log")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
