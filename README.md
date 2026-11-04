# AI Security Engineering Lab

## Why I built this

I'm an infrastructure engineer with nearly 15 years of experience working with enterprise Linux, networking, virtualization, identity integrations, and application infrastructure. My work as a customer-facing technical consultant has also involved hybrid cloud environments.

As I've been expanding into cloud-native infrastructure, Python, cybersecurity, and AI engineering, I wanted to understand how familiar security principles—least privilege, authorization, monitoring, and incident response—apply to LLM applications and AI agents.

I built this lab to explore those questions using local models, Python, Docker, and Wazuh. I used ChatGPT and Codex for AI-assisted development throughout the project. I personally run, validate, and troubleshoot the environment, with a focus on getting the components working together, testing controls, investigating failures, and understanding the engineering decisions behind them.

## What I built

- Local Ollama/Qwen3 inference through a Python client.
- Synthetic financial customer records with customer-level access controls.
- Scoped, read-only agent tools with application-enforced authorization.
- Controlled prompt injection experiments using lower-trust content.
- Structured security telemetry and custom Wazuh detections.
- Evidence-grounded investigation drafts with explicit human approval.
- GitHub Actions testing, dependency auditing, and secret scanning.

FastAPI exposes only `GET /healthz`. Inference, tools, and investigations run through internal Python modules and CLI demonstrations.

## Interesting problems encountered

### Incomplete Qwen generations

The initial `qwen3:4b` model returned incomplete reasoning-like text with `done=true` and `done_reason=length`. The client accepted it because it checked completion without checking the reason.

The investigation led to stricter validation: responses must have `done=true` and `done_reason=stop`. I then switched normal inference to `qwen3:4b-instruct`, which returned the expected result in direct API and Python-client tests. The original thinking model remains experimental.

[Investigation: generation truncation](docs/investigations/001-ollama-generation-truncation.md)

### Keeping authorization outside the model

A model-generated instruction cannot grant access to another customer's records or expand an agent's permissions. Trusted Python code supplies the fixture identity, validates the proposal, and checks both service permissions and customer scope before a tool executes.

Offline tests deliberately supply malicious proposals to verify cross-customer denial, rejected identity overrides, and unknown-tool rejection. This tests the authorization boundary even when the proposed operation is unsafe.

[Authorization experiments](docs/validation/milestone-04-prompt-injection-authorization.md) · [Scoped-tool design](docs/security-decisions/ADR-0004-scoped-agent-tools.md)

### Connecting application decisions to Wazuh

Five actual Python authorization denials produced five indexed Wazuh alerts. The observed rules were `100602`, `100603`, `100604`, `100605`, and `100610`; repeated same-service failures reached level 10. Existing SSH detection remained functional.

Correlation expiration is still unresolved. Not sure what's going on there - need to revisit. An early test did not establish the actual processing interval, and a later synchronized test stopped on a harness cleanup defect. I documented both rather than treating them as a confirmed rule failure.

[Authorization detection investigation](docs/investigations/003-ai-agent-authorization-detection.md) · [Correlation investigation](docs/investigations/002-wazuh-correlation-expiry.md)

## How to run it

From the repository root on Linux with Python 3.14:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install --no-deps -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m app.prompt_injection_demo
.venv/bin/python -m app.scoped_agent
.venv/bin/python -m app.telemetry_demo
.venv/bin/python -m app.soc_investigation
```

Installation needs PyPI access. Tests and default demonstrations use mocks and require neither Ollama nor Wazuh. The SOC command creates a Draft; add `--review` to inspect it and enter `APPROVE` or `REJECT`. Approved reports stay in ignored `local/investigations/approved/`.

To run the health-only API:

```bash
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Keep loopback binding. `GET /healthz` returns `{"status":"ok"}`; Swagger, ReDoc, and OpenAPI routes are disabled.

See the [SOC guide](docs/soc-investigation.md) for opt-in live inference, [Wazuh reproduction guide](integrations/wazuh/REPRODUCE.md) for collection and rollback, and [CI guide](docs/ci/security-pipeline.md) for local scanner commands. Live experiments and Wazuh changes require deliberate opt-in and appropriate approval.

## Evidence and documentation

The latest recorded validation passed 406 application tests and 13 CI-policy checks. All three jobs passed in [GitHub Actions](https://github.com/blackbird-git/ai-security-engineering-lab/actions).

- [Evidence index](docs/portfolio-evidence.md), including the [five sanitized indexed alerts](integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json).
- [Investigation reports, eight milestones, validation records, and architecture decisions](docs/project-records.md).
- [SOC validation](docs/validation/milestone-08-soc-investigation.md): I verified a live eight-section draft citing E1–E5, explicitly approved it, and stored the report locally.
- [Publication security review](docs/publication-security-review.md).

## Limitations

This is an educational lab, not a production security platform. Customer data is synthetic, and service/reviewer identities are fixtures rather than production authentication.

The live prompt injection experiment produced no observed unauthorized request; it did not demonstrate successful model compromise or exercise the authorization boundary. Offline tests establish denial separately.

SOC reports use controlled templates and validated references, require human approval, and cannot trigger autonomous remediation. Correlation expiration remains unverified. Further limits around inference, retention, audit integrity, and CI are recorded in the [detailed documentation](docs/project-records.md#known-limitations).

## Technology stack

Python 3.14 · FastAPI/Uvicorn · HTTPX · pytest · Ollama/Qwen3 · Docker · Wazuh 4.14.9 · GitHub Actions · pip-audit · Gitleaks · actionlint. Application and CI-tool versions are pinned separately in [application requirements](requirements.txt) and [CI tooling requirements](ci/requirements.txt).
