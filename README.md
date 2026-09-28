# DenyProof

**Find protected JSON data that crosses an authorization boundary—even when the server returns `403`.**

DenyProof is a small, dependency-free pentest CLI for testing known JSON API resources across two authorized test accounts. It validates both account sessions, brackets each cross-account request with owner controls, and generates reports without copying credentials, target URLs, response bodies, or protected field values.

This is an original implementation of an established testing technique. [Autorize](https://github.com/PortSwigger/autorize) and [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) already perform authorization testing. DenyProof focuses on JSON canaries, denial-body leaks, session controls before and after each case, and minimal evidence export. No claim of world-first novelty is made.

## Install and try the demo

Python 3.10+; no third-party runtime dependencies.

```bash
git clone git@github.com:b17w1z4rd/denyproof.git
cd denyproof
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
denyproof demo --out reports/demo
cat reports/demo/report.md
```

The demo starts a temporary API on loopback, tests it, then shuts it down. **Exit code 1 is expected** because two planted leaks are found:

| Demo endpoint | Behavior for Bob | Expected outcome |
| --- | --- | --- |
| `leaky-200` | Returns Alice's protected canary with HTTP 200 | Exposure |
| `leaky-403` | Returns Alice's protected canary with HTTP 403 | Exposure |
| `secure` | HTTP 403 and a generic error | No exposure observed |
| `login-page` | HTML login page | Inconclusive |
| `redirect` | Redirects to another origin | Inconclusive; never followed |

## Real pentest workflow

1. Choose two test accounts within your engagement scope: an owner and a subject that **must not** read the owner's resource.
2. Seed an owner-controlled resource with a distinctive test string, such as `pentest-invoice-7c4d79fa`. Prefer synthetic canaries over actual customer data.
3. Identify a `/me`-style JSON endpoint that proves which account a token belongs to.
4. Create a config under the ignored `configs/` directory. Every case means the subject is expected to be denied the owner's resource.
5. Set the token environment variables, validate the config, and run it.

```json
{
  "origin": "https://api.your-lab.example",
  "identities": {
    "alice": {
      "token_env": "ALICE_TOKEN",
      "probe": {"path": "/me", "pointer": "/id", "equals": "account-alice"}
    },
    "bob": {
      "token_env": "BOB_TOKEN",
      "probe": {"path": "/me", "pointer": "/id", "equals": "account-bob"}
    }
  },
  "cases": [{
    "id": "alice-invoice-as-bob",
    "path": "/invoices/12345",
    "owner": "alice",
    "subject": "bob",
    "proof": [{"pointer": "/invoice/note", "equals": "pentest-invoice-7c4d79fa"}]
  }]
}
```

Bash example, avoiding credentials in shell history:

```bash
read -rsp 'Alice token: ' ALICE_TOKEN; echo
read -rsp 'Bob token: ' BOB_TOKEN; echo
export ALICE_TOKEN BOB_TOKEN
denyproof validate configs/engagement.json
denyproof run configs/engagement.json --out reports/engagement --interval 0.25 --timeout 5
unset ALICE_TOKEN BOB_TOKEN
```

Tokens are sent only as `Authorization: Bearer ...` to the configured origin. `origin` defines the request destination; paths must be relative to it. Credentials are never automatically forwarded through redirects. The tool uses the normal TLS trust store, ignores proxy environment settings, does not save cookies, and does not retry requests. Use HTTPS outside the local lab. Choose GET endpoints that do not mutate data: HTTP GET alone cannot guarantee that an application has no side effects.

## How a case works

1. Verify the owner and subject sessions using the configured account ID assertions.
2. Request the target resource as the owner and require a 2xx response containing **all** configured canaries.
3. Request the same resource as the subject.
4. Repeat the owner control and both session probes.
5. If controls stayed valid, look for **any** configured protected canary in the subject's JSON body, regardless of HTTP status.

A successful full case sends seven sequential GET requests. Failed preflight checks stop a case early. The default interval is 100 ms between request starts, socket timeout is 5 seconds, and maximum body size is 1 MiB. The timeout applies to socket operations, not a total scan deadline. You can lower the request rate with `--interval` and change the body cap with `--max-bytes` (up to 10 MiB).

JSON pointers follow RFC 6901, including escaped keys and array indexes. Repeated JSON keys and nonfinite numbers are rejected. Proof strings must be at least eight characters; use unique resource-specific canaries rather than generic names. Paths, assertions, and account identifiers are supplied by the tester; the tool does not discover object IDs or generate attacks.

## Verdicts and automation

| Verdict | Meaning |
| --- | --- |
| `exposure` | A protected canary appeared at its configured pointer in the subject response while controls were valid |
| `no_exposure_observed` | HTTP 401/403/404 with valid JSON and none of the configured canaries |
| `review` | Other HTTP status without a matching configured canary |
| `inconclusive` | Session/control failure, non-JSON response, redirect, oversized body, or network error |

Exit codes: `0` only no-exposure results; `1` one or more exposures; `2` configuration problems, inconclusive cases, or manual-review results (when no exposures exist).

**No exposure observed is not a security certification.** Fields may move, be transformed, be encoded differently, or leak outside your configured assertions. A canary leak confirms a boundary failure only if your expected authorization policy is correct. HTTP status, response length, and similarity alone do not establish a vulnerability.

## Evidence handling

Reports are `report.json` and `report.md`. They include safe case/identity labels, statuses, control outcomes, assertion indexes, and a per-run HMAC for each matched canary. Identical canaries have identical fingerprints within a run. The random HMAC key is discarded, so fingerprints cannot be reproduced independently or correlated across runs. The report is a record of the tool's checks, not cryptographic attestation of server behavior.

Reports omit origin URLs, request paths, header values, full bodies, JSON pointers, and canary plaintext. Do not embed sensitive information in case IDs or identity labels; those labels appear in reports. Config files can contain sensitive paths/account IDs/canaries, so keep them under `configs/`, which is ignored by Git. Reports are ignored too. Share only after reviewing the resulting files.

## Develop and test

```bash
python -m unittest discover -s tests -v
python -m denyproof demo --out reports/demo
```

Tests use a real local HTTP server and cover 200/403 leaks, secure denial, session expiry, changed controls, redirect handling, body limits, JSON validation, request scope, and report redaction. GitHub Actions runs the suite on Python 3.10 and 3.12.

MIT licensed. The current version supports bearer-token JSON APIs and GET requests. Cookie sessions, anonymous testing, browser workflows, response transformation rules, and write requests are not implemented.
