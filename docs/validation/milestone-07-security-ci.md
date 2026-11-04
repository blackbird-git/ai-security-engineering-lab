# Milestone 7: GitHub Actions security pipeline validation

- Date: November 4, 2026
- Status: Implemented and locally validated; first GitHub-hosted run pending
- Decision: [ADR-0006, Accepted](../security-decisions/ADR-0006-security-ci.md)
- Workflow: [security-ci.yml](../../.github/workflows/security-ci.yml)
- Reproduction and design: [security pipeline guide](../ci/security-pipeline.md)

## Local automated evidence

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **328 passed**, one existing Starlette/HTTPX deprecation warning, 0.44 seconds; run outside sandbox because of the previously documented TestClient hang |
| `.venv/bin/python -m pip check` | No broken requirements found; existing disabled-cache permissions warning |
| Isolated tooling `python -m pip check` | No broken requirements found; same cache warning |
| Isolated tooling `python -m unittest discover -s ci -p workflow_policy.py -v` | **13 passed**; separate from application pytest count |
| `local/ci/bin/actionlint -shellcheck= .github/workflows/security-ci.yml` | Exit 0; GitHub Actions YAML and expressions accepted; optional shellcheck not run |
| `git diff --check` | Passed |

Policy checks parse YAML, reject duplicate mapping keys, enforce the exact triggers/read-only permissions/hosted runner, full-SHA action allowlist, Python version, no retained credentials, no suppressed failures or privileged job settings, and no event interpolation into shell commands. Negative mutations verify rejection of unsafe settings. The full suite executes once and retains authorization, scoped-tool, injection, Ollama mock, and telemetry regression modules. Application code, tests, and `requirements.txt` were not changed.

## Scanner evidence

Installed only isolated CI tooling under ignored `local/ci/`; no application package changes. The separately resolved tooling manifest pins direct and transitive packages. Verified release/tag API references for checkout v7.0.1 and setup-python v7.1.0 against the official action repositories. Verified downloaded binary archives against pinned SHA-256 values from official release checksum files.

| Scanner | Version | Local execution and result |
| --- | --- | --- |
| PyPA pip-audit | 2.10.1 | `local/ci/tooling-venv/bin/python -m pip_audit --strict --progress-spinner off --no-deps --disable-pip -r requirements.txt`: exit 0, **No known vulnerabilities found** |
| Gitleaks | 8.30.1 | `python ci/scan_secrets.py local/ci/bin/gitleaks`: exit 0, no leaks found in six reachable commits and the current nonignored source snapshot |
| actionlint | 1.7.12 | Exit 0 as above; action SHAs verified separately rather than inferred from syntax alone |

pip-audit warned that fully hashed pins are recommended for `--no-deps`; the repository uses exact version pins without hashes. No advisory ignore or automatic dependency remediation was used. No dependency vulnerability was discovered by this run; that is not proof of no vulnerabilities.

A separate fake-token positive control was generated solely in ignored temporary storage. Gitleaks rejected it with exit 1. Raw output was withheld and the temporary fixture was removed. This verifies basic failure behavior without adding a secret-like fixture to Git history. No real credentials were used by the scanners, and no raw match report was published.

## Scope and GitHub-side verification still required

No workflow was dispatched, committed, or pushed during implementation. No local Ollama requests, Wazuh/Docker operations, other-repository changes, deployments, or production credential access occurred. Public PyPI/GitHub metadata, advisory lookups, and isolated scanner downloads were necessary for the requested checks. Tests remained offline.

After separately approved publication, verify all three jobs in GitHub Actions on main/PR/manual triggers, the Python 3.14 hosted environment, checkout/setup-python execution, fork-PR permission behavior, and network availability. Configure required checks/branch protection separately; local policy tests cannot enforce remote settings. The README status is explicitly pending hosted validation rather than a claimed successful run.

Remaining risks include upstream supply-chain compromise, mutable runner/Python patch/bootstrap-pip versions, unhashed package pins, advisory database coverage/freshness and availability, scanner false positives/negatives, and workflow changes that can modify their own tests. Gitleaks scans fetched reachable history and nonignored source; ignored local logs/private configuration are outside scan coverage and must remain private. The workflow does not deploy and does not establish production readiness or validate the live SIEM.
