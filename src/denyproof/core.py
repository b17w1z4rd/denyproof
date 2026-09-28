"""No credentials, response bodies, or protected field values enter reports."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import math
import os
import re
import secrets
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


def pointer(value, path):
    """Resolve an RFC 6901 JSON Pointer. A missing value raises KeyError."""
    if path == "":
        return value
    if not isinstance(path, str) or not path.startswith("/"):
        raise KeyError("invalid pointer")
    for raw in path[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise KeyError("invalid pointer escape")
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            if key not in value:
                raise KeyError("missing key")
            value = value[key]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
            try:
                value = value[int(key)]
            except IndexError:
                raise KeyError("missing index") from None
        else:
            raise KeyError("missing value")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def strict_json(data):
    def reject_constant(value):
        raise ValueError("Nonfinite JSON number")
    def unique_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(data, parse_constant=reject_constant, object_pairs_hook=unique_pairs)


def safe_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
            or "#" in value or "\\" in value):
        raise ConfigError("Paths must be ASCII origin-relative paths without whitespace or fragments")
    return value


def load_config(path):
    try:
        config = strict_json(Path(path).read_text())
        validate(config)
        return config
    except ConfigError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ConfigError("Invalid configuration; consult examples/lab.json") from exc


def validate(config):
    origin = urlsplit(config["origin"])
    if (origin.scheme not in ("http", "https") or not origin.hostname or origin.username
            or origin.password or origin.path not in ("", "/") or origin.query or origin.fragment):
        raise ConfigError("origin must be one HTTP(S) origin without credentials or a path")
    _ = origin.port
    sessions = config["identities"]
    cases = config["cases"]
    if not isinstance(sessions, dict) or not sessions or not isinstance(cases, list) or not cases:
        raise ConfigError("Need identities and cases")
    if len(cases) > 200 or len(sessions) > 20:
        raise ConfigError("Maximum 200 cases and 20 identities per run")
    for name, identity in sessions.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ConfigError("Use simple identity labels")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identity["token_env"]):
            raise ConfigError("token_env must name an environment variable")
        probe = identity["probe"]
        safe_path(probe["path"])
        if not isinstance(probe["pointer"], str) or not probe["pointer"].startswith("/"):
            raise ConfigError("Session probe requires a JSON Pointer")
        if not isinstance(probe["equals"], str) or not probe["equals"]:
            raise ConfigError("Session probe equals must be a nonempty account identifier")
    names = set()
    for case in cases:
        name = case["id"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or name in names:
            raise ConfigError("Case IDs must be unique simple labels")
        names.add(name)
        safe_path(case["path"])
        if case["owner"] not in sessions or case["subject"] not in sessions:
            raise ConfigError("Unknown owner or subject identity")
        if case["owner"] == case["subject"]:
            raise ConfigError("Owner and denied subject must differ")
        if not isinstance(case["proof"], list) or not case["proof"]:
            raise ConfigError("At least one proof assertion is required")
        for assertion in case["proof"]:
            if not isinstance(assertion["pointer"], str) or not assertion["pointer"].startswith("/"):
                raise ConfigError("Proof assertions need a JSON Pointer")
            # Unique canary strings give a stronger signal than true/false, counts or null.
            if not isinstance(assertion["equals"], str) or len(assertion["equals"]) < 8:
                raise ConfigError("Proof values must be unique canary strings at least 8 characters long")
    return config


class Client:
    """One configured origin; no proxies, redirects, retries, or shared cookies."""
    def __init__(self, origin, *, timeout=5., interval=.1, max_bytes=1024*1024):
        self.origin = urlsplit(origin)
        if (not math.isfinite(timeout) or not math.isfinite(interval) or timeout <= 0
                or interval < 0 or not 1 <= max_bytes <= 10*1024*1024):
            raise ConfigError("Invalid network limits")
        self.timeout, self.interval, self.max_bytes = timeout, interval, max_bytes
        self.previous = None

    def get(self, path, token):
        safe_path(path)
        if not token or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
            return {"status": None, "error": "invalid_token"}
        if self.previous is not None:
            time.sleep(max(0., self.interval - (time.monotonic() - self.previous)))
        self.previous = time.monotonic()
        klass = http.client.HTTPSConnection if self.origin.scheme == "https" else http.client.HTTPConnection
        extra = {"context": ssl.create_default_context()} if self.origin.scheme == "https" else {}
        connection = klass(self.origin.hostname, self.origin.port, timeout=self.timeout, **extra)
        try:
            connection.request("GET", path, headers={"Authorization": "Bearer " + token,
                               "Accept": "application/json", "Accept-Encoding": "identity",
                               "Cache-Control": "no-cache", "User-Agent": "DenyProof/0.1"})
            response = connection.getresponse()
            status = response.status
            body = response.read(self.max_bytes + 1)
            result = {"status": status, "bytes_read": min(len(body), self.max_bytes)}
            if len(body) > self.max_bytes:
                return {**result, "error": "body_limit"}
            if 300 <= status < 400:
                return {**result, "error": "redirect_not_followed"}
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                return {**result, "error": "unsupported_encoding"}
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json" and not (content_type.startswith("application/")
                                                           and content_type.endswith("+json")):
                return {**result, "error": "non_json"}
            try:
                return {**result, "json": strict_json(body)}
            except (ValueError, UnicodeError, RecursionError):
                return {**result, "error": "invalid_json"}
        except (OSError, http.client.HTTPException, ValueError):
            # Exception strings can contain target or credential details; never report them.
            return {"status": None, "error": "transport_error"}
        finally:
            connection.close()


def matches(response, assertions):
    if "json" not in response:
        return []
    found = []
    for index, assertion in enumerate(assertions):
        try:
            if pointer(response["json"], assertion["pointer"]) == assertion["equals"]:
                found.append(index)
        except KeyError:
            pass
    return found


def summary(response):
    return {k: response[k] for k in ("status", "bytes_read", "error") if k in response}


def run(config, client=None, env=None):
    validate(config)
    client = client or Client(config["origin"])
    env = os.environ if env is None else env
    tokens = {}
    for name, identity in config["identities"].items():
        value = env.get(identity["token_env"])
        if not value:
            raise ConfigError("A required token environment variable is missing")
        if any(ord(c) <= 32 or ord(c) >= 127 for c in value):
            raise ConfigError("Tokens must be printable ASCII without whitespace")
        tokens[name] = value
    key = secrets.token_bytes(32)  # Discarded after the run: no offline canary dictionary oracle.

    def probe(name):
        spec = config["identities"][name]["probe"]
        response = client.get(spec["path"], tokens[name])
        valid = (response.get("status") == 200 and matches(response, [spec]) == [0])
        return valid, summary(response)

    results = []
    for case in config["cases"]:
        owner, subject = case["owner"], case["subject"]
        row = {"case": case["id"], "owner": owner, "subject": subject,
               "verdict": "inconclusive", "evidence": []}
        before = {name: probe(name) for name in (owner, subject)}
        row["session_before"] = {name: {"valid": val[0], **val[1]} for name, val in before.items()}
        if not all(v[0] for v in before.values()):
            row["reason"] = "session_preflight_failed"
            results.append(row)
            continue
        positive_before = client.get(case["path"], tokens[owner])
        assertions = case["proof"]
        row["owner_before"] = summary(positive_before)
        if (positive_before.get("status") not in range(200, 300)
                or len(matches(positive_before, assertions)) != len(assertions)):
            row["reason"] = "owner_positive_control_failed"
            results.append(row)
            continue
        negative = client.get(case["path"], tokens[subject])
        positive_after = client.get(case["path"], tokens[owner])
        after = {name: probe(name) for name in (owner, subject)}
        row["subject_response"] = summary(negative)
        row["owner_after"] = summary(positive_after)
        row["session_after"] = {name: {"valid": val[0], **val[1]} for name, val in after.items()}
        if (not all(v[0] for v in after.values()) or positive_after.get("status") not in range(200, 300)
                or len(matches(positive_after, assertions)) != len(assertions)):
            row["reason"] = "control_changed_during_test"
        elif "error" in negative:
            row["reason"] = negative["error"]
        else:
            leaked = matches(negative, assertions)
            if leaked:
                row["verdict"] = "exposure"
                row["reason"] = "protected_canary_returned_to_denied_subject"
                for i in leaked:
                    # Index maps to local config; avoid copying paths, values or target URL.
                    digest = hmac.new(key, canonical(assertions[i]["equals"]), hashlib.sha256).hexdigest()
                    row["evidence"].append({"assertion_index": i, "owner_and_subject_hmac": digest})
            elif negative.get("status") in (401, 403, 404):
                row["verdict"] = "no_exposure_observed"
                row["reason"] = "denial_without_configured_canaries"
            else:
                row["verdict"] = "review"
                row["reason"] = "unexpected_status_without_configured_canaries"
        results.append(row)
    counts = {name: sum(r["verdict"] == name for r in results)
              for name in ("exposure", "no_exposure_observed", "review", "inconclusive")}
    return {"tool": "denyproof", "version": "0.1.0", "summary": counts, "cases": results,
            "limitations": "Checks only configured canaries; no exposure observed is not proof of complete authorization enforcement."}


def markdown(report):
    lines = ["# DenyProof evidence report", "", "| Case | Owner | Subject | HTTP | Verdict |",
             "| --- | --- | --- | --- | --- |"]
    for row in report["cases"]:
        status = row.get("subject_response", {}).get("status", "—")
        lines.append(f"| {row['case']} | {row['owner']} | {row['subject']} | {status} | {row['verdict']} |")
    lines.extend(["", report["limitations"], "", "Details are in the accompanying JSON report.", ""])
    return "\n".join(lines)


def save_report(report, destination):
    path = Path(destination)
    path.mkdir(parents=True, exist_ok=True)
    for name, content in (("report.json", json.dumps(report, indent=2) + "\n"),
                          ("report.md", markdown(report))):
        target = path / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
    return path
