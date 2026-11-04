# Publication security and accuracy review

- Date: November 4, 2026
- Baseline: commit `e31541681612a30a7b8df0c4630e1fdda0983489`
- Disposition: Publication preparation complete; owner accepts existing Git author/contact disclosure; history preserved
- Changes in this preparation: README, documentation, and prose path corrections only; no history rewrite, deletion, visibility change, infrastructure operation, or application functionality change; documentation commit/push authorized for finalization

## Scope and method

Reviewed the 65 tracked baseline files, documentation/evidence/configuration/workflow contracts, locally reachable history (8 commits, 65 unique historical paths, 74 unique blobs), and Git author metadata. Enumerated historical trees rather than assuming current ignore patterns removed earlier files. Inspected the sanitized indexed-alert artifact and illustrative JSONL samples, the read-only manager bind/localfile examples, custom rules, CI workflow/tooling, and runtime exclusion patterns.

Gitleaks 8.30.1 scanned all locally reachable commits plus the nonignored working source. PyPA pip-audit 2.10.1 checked the pinned application manifest against advisory data without changing dependencies. Binary/archive filenames, credential/runtime paths, host paths, private IPv4 literals, and author metadata were also checked independently. No screenshots/PDFs or binary blobs were found in tracked/reachable history. No local private configuration, backup contents, credentials, or approved report bodies were copied into this review.

This is a bounded repository review, not a guarantee against undiscovered secrets. Unreachable/dangling objects, deleted remote refs, GitHub caches, external forks, remote artifacts, ignored file contents, and the separate SIEM repository are outside coverage. Do not upload the working directory as an archive: ignored files remain private and have not been certified safe.

## Findings and owner decisions

| Finding | Publication significance | Disposition |
| --- | --- | --- |
| Personal author name and personal email in Git commit metadata | Making history public discloses this identity/contact information; secret scanners do not classify it as a credential | Owner explicitly accepts publication of existing author metadata, including the personal email address. Preserve all commits. Values are not repeated here. No author configuration/history was changed. |
| Absolute home-directory paths and local username in validation/deployment examples | Host/account-identifying metadata and reduced portability, even without credentials | Unnecessary prose paths now use repository-relative notation. Required absolute deployment examples remain; historical copies remain because history is preserved. No active configuration artifact was changed. |
| Lab topology and identifiers | Container/service names, agent IDs, log/config paths, SHA-256 checksums, detection dates, request UUIDs, and index name reveal a lab layout | Reviewed security metadata, not authentication material. Retained as necessary reproducibility/evidence metadata; no credentials or private configuration contents are included. Do not replace IDs/timestamps arbitrarily because the SOC reader pins the artifact. |
| No credentials or real customer records identified | Gitleaks found no leaks; financial records are explicitly synthetic fixtures; dummy secret sentinel and hostile strings are test inputs | No credential remediation identified by this review. Scanner false negatives remain possible. |
| No runtime or credential filenames ever tracked in inspected history | No tracked `local/`, `.venv/`, `.env`, credential directories, private keys, packet captures, or databases were found | Existing ignores cover environments, runtime reports/logs, backups, private configuration, and common credential formats. Ignoring alone does not certify file contents safe. |
| No RFC1918 address literals identified in inspected text blobs | Loopback inference addresses are documented; no private-network address redaction was identified | Not a scan for every possible internal DNS/IPv6 identifier; lab names/paths are separately noted above. |
| Stale preparation comments in Wazuh artifacts | XML/Compose comments still describe candidates or not-yet-tested rules | Historical labels do not supersede the later integration records. Artifacts were left byte-for-byte unchanged to preserve deployed checksum references; README links actual validation. |

Baseline files containing literal home-directory paths in current/reachable versions (prose is now simplified; historical copies are retained):

- `docs/validation/milestone-02-fastapi-baseline.md`
- `docs/validation/milestone-03-ollama-integration.md`
- `docs/validation/milestone-04-prompt-injection-authorization.md`
- `docs/validation/milestone-06-collection-preparation.md`
- `docs/validation/milestone-06-end-to-end-wazuh-integration.md`
- `integrations/wazuh/COLLECTION-PLAN.md`
- `integrations/wazuh/PHASE-B-PROCEDURE.md`
- `integrations/wazuh/compose.collection.example.yml`

The Compose example contains only two read-only binds, not the private manager configuration or Docker secret contents. Deployment instructions deliberately create private copies/backups under ignored `local/`; publishing those copies would expose substantially more information than the examples. Do not edit the active override or rewrite history merely to improve portfolio appearance. Any desired anonymization/history rewrite needs a separately reviewed owner-approved procedure.

## Evidence and claim accuracy

- The live prompt-injection experiment did not demonstrate successful compromise or an unauthorized request. Offline malicious proposals independently demonstrated Python authorization denial.
- Five fresh application authorization-denial events were verified in manager alerts and the indexer. Within-window same-service correlation reached rule 100610/level 10; expiration is still unverified, not a confirmed rule defect.
- The SOC workflow has owner-verified live generation and explicit approval, with fixture reviewer context. It does not provide production authentication, tamper-resistant approval auditing, or autonomous remediation.
- Event timestamps are preserved verbatim. Equal timestamps and E1–E5 display order do not establish a finer event sequence.
- CI is verified for a push run. Required-check configuration, fork-PR behavior, and manual dispatch are not claimed verified.
- This is an AI-assisted engineering/portfolio lab, not a production security platform or evidence of professional production SOC experience.

See [the evidence index](portfolio-evidence.md) for the strongest records and missing manual screenshot captures. No screenshots were manufactured and no private runtime report is linked for publication.

## Checks and limits

Final local validation results: Existing warnings and known limits remain: unhashed dependency pins, mutable runners/Python patch versions, point-in-time advisory/secret coverage, unauthenticated loopback inference, fixture identities, unsigned events/reports, missing retention/rotation, unverified correlation expiration, and no inspected dashboard UI. The owner author/contact decision is recorded above; scanner coverage remains bounded.

| Check | Result |
| --- | --- |
| Full `.venv/bin/python -m pytest -q` | **406 passed** in 0.45 seconds outside the sandbox; one existing Starlette/HTTPX deprecation warning |
| Existing CI workflow-policy checks | **13 passed** |
| Application `pip check` | No broken requirements; existing disabled-cache permissions warning |
| Gitleaks 8.30.1 | No leaks found in 8 reachable commits or nonignored source |
| pip-audit 2.10.1 | No known vulnerabilities found; existing recommendation to hash pinned dependencies |
| actionlint 1.7.12 | Workflow accepted; optional shellcheck not run |
| Whitespace and README local links | Passed |
| Mermaid | Flowchart structure, delimiters, and node references checked; no installed Mermaid parser/browser renderer, so full syntax/render validation is not claimed |

Existing author/contact publication is explicitly approved; no history rewrite or force push is permitted. No technical publication blocker was identified in the reviewed material. Preview Mermaid on GitHub and optionally capture/review the screenshots listed in the evidence index before changing visibility. Necessary nonsecret lab paths/topology and historical copies remain documented, not anonymized. No private report or screenshot is needed to reproduce the offline controls. No repository visibility/settings were changed.

## Final publication-preparation approval

The owner explicitly accepts publication of existing Git author information, including the personal email address, and directs preservation of history. Finalization revalidated 406 application tests, 13 CI-policy checks, dependency consistency, Gitleaks, pip-audit, local links, and whitespace checks. The cited hosted run was checked through GitHub CLI and all three jobs were confirmed successful. Only ten Markdown files are included; no local runtime material, configuration artifact, application code, dependency, or evidence bytes change. The publication commit/push is authorized; visibility changes and force pushes are not.
