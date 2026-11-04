# Portfolio evidence and manual captures

Use recorded results to assess specific controls. A CLI mock is not live model behavior, a rule-only logtest is not proof of indexed delivery, and an alert is not proof of a successful attack. Historical preparation/rollback records remain available and should be read alongside the later end-to-end validation.

## Strongest available evidence

| Evidence | What it supports | Boundary |
| --- | --- | --- |
| [Five sanitized indexed alerts](../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json) | Exact correlation IDs, source/detection timestamps, rule IDs, levels, and indexed verification | Security metadata only, not raw logs; previous owner-verified synthetic run |
| [Authorization detection investigation](investigations/003-ai-agent-authorization-detection.md) and [integration record](validation/milestone-06-end-to-end-wazuh-integration.md) | Actual Python-to-JSONL-to-Wazuh-to-indexer chain, SSH regression and preserved configuration checksums | Expiration unverified; dashboard UI not inspected |
| [Passing hosted CI run 41908231336](https://github.com/blackbird-git/ai-security-engineering-lab/actions/runs/41908231336) | Three successful jobs for commit `e31541681612a30a7b8df0c4630e1fdda0983489` | Point-in-time hosted push run; link access depends on repository visibility |
| [SOC workflow validation](validation/milestone-08-soc-investigation.md) | Owner-verified local generation, eight cited sections, explicit approval and local storage | Private approved report intentionally not published; fixture reviewer channel |
| [Prompt-injection validation](validation/milestone-04-prompt-injection-authorization.md) and [authorization tests](../tests/test_authorization.py) | Live injection did not elicit an unauthorized request; offline tests verify denial even under malicious proposals | No successful live model compromise or exercised live authorization boundary was observed |

The reviewed indexed artifact has five events with identical source timestamps `2026-11-04T19:55:05.433Z` and identical detection timestamps `2026-11-04T19:55:06.488+0000`. E1–E5 and presentation order are references, not evidence of finer chronological ordering.

## Screenshots not yet available

No screenshots, diagrams as image files, or PDFs were found in the tracked tree or reachable commit history. None were fabricated. The README Mermaid diagram is a textual architecture visualization, not runtime evidence.

If visual evidence is desired, the owner can manually capture:

1. The completed GitHub Actions run, showing commit and the three successful jobs.
2. A local offline authorization/tool demo showing an allowed read and denied cross-customer/identity-override attempts, without financial payloads.
3. The sanitized five-alert metadata table with exact correlation IDs and rule 100610 at level 10. A dashboard screenshot would require a new manual observation and must not be represented as the earlier unperformed UI validation.
4. A fresh synthetic SOC review showing Draft, evidence citations, the explicit approval prompt, and the approved outcome. Do not publish a private approved runtime report; use only a separately reviewed sanitized excerpt/capture.

Before adding any capture, inspect the actual image for browser account/avatar information, email, hostnames, terminal paths, browser tabs, URLs, credentials, unrelated alerts, and other lab configuration. Do not display environment variables, Docker inspect output, manager configuration, TLS keys, or private backup contents. Record when a new capture was made and whether it shows a mock, live inference, or actual SIEM result. Screenshots would be new publication material requiring review; this task did not capture a UI or change infrastructure.
