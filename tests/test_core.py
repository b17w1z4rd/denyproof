import copy
import json
import tempfile
import unittest
from pathlib import Path
from denyproof.core import Client, ConfigError, canonical, load_config, pointer, run, save_report, strict_json
from denyproof.lab import CANARY, configuration, lab

ENV = {"ALICE_TOKEN": "lab-alice-token", "BOB_TOKEN": "lab-bob-token"}


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab_context = lab()
        cls.origin = cls.lab_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.lab_context.__exit__(None, None, None)

    def test_real_http_findings_and_redaction(self):
        config = configuration(self.origin)
        report = run(config, Client(self.origin, interval=0), ENV)
        rows = {r["case"]: r for r in report["cases"]}
        self.assertEqual(rows["leaky-200"]["verdict"], "exposure")
        self.assertEqual(rows["leaky-403"]["verdict"], "exposure")
        self.assertEqual(rows["leaky-403"]["subject_response"]["status"], 403)
        self.assertEqual(rows["secure"]["verdict"], "no_exposure_observed")
        self.assertEqual(rows["login-page"]["reason"], "non_json")
        self.assertEqual(rows["redirect"]["reason"], "redirect_not_followed")
        with tempfile.TemporaryDirectory() as d:
            save_report(report, d)
            for path in Path(d).iterdir():
                text = path.read_text()
                for secret in (CANARY, ENV["ALICE_TOKEN"], ENV["BOB_TOKEN"], self.origin):
                    self.assertNotIn(secret, text)
        self.assertEqual(rows["leaky-200"]["evidence"][0]["owner_and_subject_hmac"],
                         rows["leaky-403"]["evidence"][0]["owner_and_subject_hmac"])

    def test_invalid_session_never_becomes_finding(self):
        report = run(configuration(self.origin), Client(self.origin, interval=0),
                     {**ENV, "BOB_TOKEN": "expired-token"})
        self.assertEqual(report["summary"]["inconclusive"], 5)
        self.assertEqual(report["summary"]["exposure"], 0)

    def test_wrong_owner_canary_is_inconclusive(self):
        config = configuration(self.origin)
        config["cases"] = config["cases"][:1]
        config["cases"][0]["proof"][0]["equals"] = "nonexistent-canary"
        report = run(config, Client(self.origin, interval=0), ENV)
        self.assertEqual(report["cases"][0]["reason"], "owner_positive_control_failed")

    def test_response_limit(self):
        response = Client(self.origin, interval=0, max_bytes=8).get("/me", ENV["ALICE_TOKEN"])
        self.assertEqual(response["error"], "body_limit")
        self.assertNotIn("json", response)

    def test_changed_owner_control(self):
        base = Client(self.origin, interval=0)
        class ChangingClient:
            def __init__(self):
                self.owner_reads = 0
            def get(self, path, token):
                if path == "/leaky-200" and token == ENV["ALICE_TOKEN"]:
                    self.owner_reads += 1
                    if self.owner_reads == 2:
                        return {"status": 200, "json": {"invoice": {"canary": "rotated-canary"}}}
                return base.get(path, token)
        config = configuration(self.origin)
        config["cases"] = config["cases"][:1]
        report = run(config, ChangingClient(), ENV)
        self.assertEqual(report["cases"][0]["reason"], "control_changed_during_test")
        self.assertEqual(report["summary"]["exposure"], 0)

    def test_per_run_fingerprint_randomness(self):
        config = configuration(self.origin)
        config["cases"] = config["cases"][:1]
        a = run(config, Client(self.origin, interval=0), ENV)
        b = run(config, Client(self.origin, interval=0), ENV)
        self.assertNotEqual(a["cases"][0]["evidence"], b["cases"][0]["evidence"])


class UnitTests(unittest.TestCase):
    def test_json_pointer_escape_and_array(self):
        self.assertEqual(pointer({"a/b": [{"~x": 42}]}, "/a~1b/0/~0x"), 42)
        for path in ("/a~2b", "/a~1b/01", "/a~1b/-1", "/missing"):
            with self.assertRaises(KeyError):
                pointer({"a/b": [5]}, path)

    def test_strict_json(self):
        for text in ('{"x": 1, "x": 2}', '{"x": NaN}'):
            with self.assertRaises(ValueError):
                strict_json(text)
        self.assertEqual(canonical({"b": 2, "a": 1}), canonical({"a": 1, "b": 2}))

    def test_reject_out_of_origin_paths_and_missing_tokens(self):
        for path in ("https://other.test/a", "//other.test/a", "/a\r\nHost: evil", "/a#fragment"):
            config = configuration("http://127.0.0.1:1")
            config["cases"][0]["path"] = path
            with self.assertRaises(ConfigError):
                run(config, env=ENV)
        with self.assertRaises(ConfigError):
            run(configuration("http://127.0.0.1:1"), env={})

    def test_configuration_read_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "invalid.json"
            path.write_text('{"origin": 42}')
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
