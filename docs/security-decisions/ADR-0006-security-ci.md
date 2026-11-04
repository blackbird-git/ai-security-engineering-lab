# ADR-0006: Read-only GitHub Actions security validation

- Status: Accepted
- Date: 2026-11-04
- Scope: Milestone 7 workflow and local validation; hosted execution pending

## Decision

Use three GitHub-hosted Ubuntu jobs on main pushes, main-targeting pull requests, and manual dispatch. Grant only `contents: read`; use verified full-SHA checkout/setup-python actions, disable persisted credentials, and select Python 3.14. Do not use `pull_request_target`, self-hosted runners, deployments, repository writes, secrets, local inference, Docker, or Wazuh. Existing FastAPI and application security boundaries remain unchanged.

Run the full pytest suite once, covering existing authorization/tool/telemetry negative controls, followed by application `pip check`. Install the exact application manifest in its own environment. Isolate pinned PyPA pip-audit and PyYAML tooling in a separate environment and manifest with resolved transitive versions. Audit the unchanged pinned application list using `--strict --no-deps --disable-pip`; never automatically update dependencies or suppress advisory failures.

Use the open-source Gitleaks CLI without its licensed Action/service integration. Verify the pinned official binary archive SHA-256 before extracting only its executable. Scan fetched history and nonignored source with full redaction and built-in rules, disabling project configuration/ignore and inline suppression overrides. Keep runtime files excluded from the source snapshot. No raw scanner report is uploaded. Pin actionlint similarly to validate Actions syntax; independent YAML policy checks test permissions, triggers, runners, failure handling, SHA references, and regression execution.

## Rationale and consequences

Hosted, short-lived, unprivileged jobs limit impact of executing pull-request code. No trusted deployment context is exposed. Independent jobs avoid concealing audit findings behind an unrelated test failure. A single full suite avoids duplicate execution of the existing security regressions. Separate tooling prevents scanner dependency resolution from altering the application environment. Explicit failures preserve visibility for findings and infrastructure failures.

Pins and checksums improve reproducibility but do not make upstream code inherently trustworthy. Python patch versions, runner images, and bootstrap pip can change; package manifests are not hash locks. Known-vulnerability auditing needs public network/advisory services and cannot detect unknown flaws or all malicious packages. Gitleaks has heuristic false positives/negatives and built-in allowlists; scans cover reachable history/source rather than ignored private runtime data. Workflow configuration and its tests can be changed together by a PR, so review and separately configured required checks remain necessary. No deployment/CD promotion is implemented.

## Validation and pending review

The [validation record](../validation/milestone-07-security-ci.md) distinguishes local tests/scans from unexecuted GitHub jobs. The [operation guide](../ci/security-pipeline.md) documents exact commands, verified references, triage, and limitations. Hosted runs, branch protection requirements, fork-PR behavior, and action execution on the runner remain pending; acceptance covers only the locally validated pipeline design, not unverified hosted execution. No Wazuh/Docker or other-repository changes are authorized by this decision.
