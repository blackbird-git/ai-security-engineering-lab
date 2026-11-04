# Security CI operation and reproduction

The [workflow](../../.github/workflows/security-ci.yml) validates pushes to `main`, pull requests targeting `main`, and manual dispatch. It uses ephemeral GitHub-hosted Ubuntu 24.04 runners and Python 3.14. It performs validation only: no deployment, publishing, live inference, Wazuh, Docker, or secrets integration exists.

## Jobs and failure behavior

| Job | Checks |
| --- | --- |
| `tests` | Install unchanged pinned application requirements without resolving additional packages in an isolated environment; run the entire pytest suite once and `pip check`. This includes authorization, tool permissions/customer scope, identity override, prompt injection, telemetry privacy/failure controls, and mock Ollama regressions. |
| `audit` | Install separately pinned CI tooling; run workflow-policy tests and actionlint; audit every exact application requirement with PyPA pip-audit. |
| `secrets` | Gitleaks scans all fetched reachable Git history and a snapshot of tracked plus nonignored untracked source. No credentials or paid service required. |

Nonzero test, scanner, installation, checksum, network/advisory-lookup, or policy errors fail the job. No `continue-on-error`, vulnerability exclusions, auto-fixes, secret baselines, or project allowlists are configured. Secret matches are fully redacted; inline `gitleaks:allow` annotations and repository ignore/config overrides are disabled for these scans. Built-in scanner heuristics/allowlists still apply. The source snapshot excludes ignored local logs, backups, private configuration, and environments; it does not certify those files safe.

The workflow grants only `contents: read`, does not retain checkout credentials, uses full commit SHA action references, and has no privileged pull-request trigger, deployment environments, repository writes, service containers, self-hosted runners, or event-controlled shell interpolation. Full history is fetched only for the secret job. There are no artifact uploads or dependency caches shared between pull requests and trusted runs. Job timeouts and concurrency bound runner use. Package installation and advisory/download queries require public network access; application tests remain offline.

## Verified tool pins

| Component | Version / reference |
| --- | --- |
| PyPA pip-audit | `2.10.1`; resolved direct/transitive tooling pins in [ci/requirements.txt](../../ci/requirements.txt) |
| PyYAML | `6.0.3`; policy-check parser only, outside application environment |
| Gitleaks | `8.30.1`; official Linux x86-64 release archive with pinned SHA-256 |
| actionlint | `1.7.12`; official Linux x86-64 release archive with pinned SHA-256 |
| actions/checkout | `v7.0.1`, `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-python | `v7.1.0`, `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` |

The two action SHAs were verified using each official GitHub repository's release/tag API on November 4, 2026. The binary digests in [install_binary.py](../../ci/install_binary.py) were checked against the official release checksum files. Downloaded bytes must match before extraction; only the single named regular binary is extracted. No third-party installer is piped into a shell. Version/checksum changes require review and retesting; these pins are not automatic updates or protection against an already compromised upstream release. Python's `3.14` selector receives patch updates; hosted images and bootstrap pip are not immutable. Python requirements are exact-version pins, not hash locks.

References: [pip-audit](https://github.com/pypa/pip-audit), [Gitleaks](https://github.com/gitleaks/gitleaks), [actionlint](https://github.com/rhysd/actionlint), [checkout release](https://github.com/actions/checkout/releases/tag/v7.0.1), [setup-python release](https://github.com/actions/setup-python/releases/tag/v7.1.0).

## Local reproduction

Run from the repository root with the existing `.venv`. The application environment is unchanged. Downloads/installations below are explicit CI-tool setup, not runtime dependencies; obtain approval where local policy requires it.

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m venv local/ci/tooling-venv
local/ci/tooling-venv/bin/python -m pip install --no-deps -r ci/requirements.txt
local/ci/tooling-venv/bin/python -m pip check
local/ci/tooling-venv/bin/python -m unittest discover -s ci -p workflow_policy.py -v
.venv/bin/python ci/install_binary.py actionlint local/ci/bin
local/ci/bin/actionlint -shellcheck= .github/workflows/security-ci.yml
.venv/bin/python ci/install_binary.py gitleaks local/ci/bin
.venv/bin/python ci/scan_secrets.py local/ci/bin/gitleaks
local/ci/tooling-venv/bin/python -m pip_audit --strict --progress-spinner off --no-deps --disable-pip -r requirements.txt
git diff --check
```

The binary installer supports Linux x86-64 only. `local/` remains ignored. actionlint checks Actions syntax/expressions; its optional shellcheck integration is disabled consistently in local and CI commands, so shellcheck coverage is not claimed. Policy tests are separate `unittest` checks in `ci/workflow_policy.py`, keeping PyYAML out of the application environment and preserving the existing 328-test suite. No security test subset is rerun after pytest.

`--no-deps --disable-pip` audits the explicitly pinned list without dependency resolution, installing application packages, or running builds. The full manifest already records resolved transitive application dependencies. `--strict` fails if collection of advisory information fails; no vulnerabilities are ignored. Installation plus `pip check` tests runtime dependency consistency separately. Audit results depend on public advisory coverage/freshness and do not establish absence of unknown vulnerabilities or malicious packages.

## Findings and GitHub acceptance

On a finding, keep the job failed, investigate redacted metadata privately, and make a reviewed fix. For a real secret, revoke/rotate it through the owner's approved process; deletion alone does not remove it from history. Do not add blanket suppressions to obtain a green check. Dependency upgrades must be a separate reviewed application change; this workflow never uses `--fix`.

After approval to publish, verify all three jobs on GitHub, Python 3.14 availability, fork-PR token behavior, and runner connectivity. Manual dispatch becomes available when the workflow exists on the default branch. Repository branch protection/rulesets must separately require all job checks; this patch does not configure them. Review workflow and `ci/` changes carefully because a pull request can edit its own checks. A passing run is point-in-time evidence, not production security certification. See [ADR-0006](../security-decisions/ADR-0006-security-ci.md) and [local validation](../validation/milestone-07-security-ci.md).
