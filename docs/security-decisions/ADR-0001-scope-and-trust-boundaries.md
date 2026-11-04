# ADR-0001: Scope and trust boundaries

- Status: Accepted
- Date: 2026-11-04
- Scope: Local AI Security Engineering Lab

## Context

This repository is a hands-on training and portfolio project. The planned stack is Python FastAPI, local Ollama running Qwen3 4B, controlled agent tools over synthetic financial data, and security telemetry delivered to Wazuh 4.14.9. No application or integration is implemented yet.

The owner reports Ubuntu 26.04 LTS, Python 3.14.4, Docker 29.8.2, and Ollama 0.40.13 with Qwen3 4B. Dependency compatibility, model configuration, and deployment topology require implementation-time validation.

## Decision

The owner has approved the scope and trust-boundary principles. Detailed authentication, authorization, network, and Wazuh implementation decisions remain pending; acceptance does not authorize those implementation choices or external operations.

Use local inference instead of paid model APIs for the lab application. Local inference supports repeatable exercises, avoids per-request API costs, and reduces disclosure to external inference providers. It does not make model behavior trustworthy or eliminate host, dependency, or network risks. Model downloads and other external operations require approval.

Use only clearly labeled synthetic financial records and identities. This enables realistic authorization and data-access scenarios without actual customer information or secrets. Synthetic records must not be derived from real customer datasets. Sanitized, reviewed fixtures and evidence may be tracked; raw local captures and runtime data belong in ignored local directories.

FastAPI owns trusted identity and policy decisions. The model can propose tool calls, but application code must validate and authorize every action and resource before execution. A prompt, retrieved document, or model response cannot grant privileges.

The initial FastAPI application may expose only static diagnostic endpoints and must bind to `127.0.0.1`. Financial records, agent tools, and sensitive operations must not be exposed until appropriate authentication and authorization controls are implemented.

Intentionally vulnerable demonstrations must be opt-in, clearly labeled, and isolated from real credentials and unrestricted tools. They must not make unapproved external connections. Use synthetic targets and bounded execution within the lab's isolation boundaries.

## Trust boundaries and required controls

| Boundary | Untrusted input or risk | Required design |
| --- | --- | --- |
| Client -> FastAPI | Spoofed identity, malformed input, unauthorized resource selection | Authenticate through a reviewed mechanism; derive permissions from trusted application context; validate input and deny unauthorized actions. |
| FastAPI -> Ollama -> application | Prompt injection, fabricated results, unsafe tool proposals | Keep inference local and access restricted; treat output as data; validate schemas and bound request size, duration, and tool-call count. |
| Retrieved content/tool responses -> model and application | Embedded instructions and hostile strings | Treat content as untrusted; preserve provenance; never convert content into authority or executable code. |
| Application dispatcher -> tools | Excess privilege, arbitrary execution, confused-deputy access | Allowlist narrow tools; check action/resource authorization on every invocation; validate arguments; prohibit arbitrary shell and unrestricted filesystem/network access. |
| Tools -> synthetic data | Cross-user access, unwanted mutation, data escape | Scope reads to authorized records; start with read-only tools; use dedicated fixtures and bounded paths; review any write capability separately. |
| Application/tools -> telemetry -> Wazuh | Sensitive payload leakage, forged events, collector privilege | Emit redacted structured events with trusted correlation context; validate and safely encode fields; restrict collector access and review transport/authentication. |
| Lab -> host, other labs, external networks | Host access, unintended exposure, uncontrolled attacks | Isolate services and exercises; default to loopback or a dedicated lab network; exclude other lab files and credentials; require approval for external operations. |

Telemetry should record event type, timestamp, correlation ID, synthetic actor/resource identifiers, requested action, authorization outcome, policy reason code, tool outcome, and bounded error metadata. Raw prompts, full model/tool responses, credentials, and financial payloads are excluded by default. Retention, integrity, transport, and access controls remain review items.

Wazuh is a separate security system, not a model-controlled tool. No model-generated configuration or unrestricted automated response is allowed. Connecting to or modifying Wazuh requires explicit approval of the target and changes before execution.

## Consequences

- The lab can exercise authorization failures, prompt injection, and tool abuse without real customer records or paid inference calls.
- Local compute and model capability constrain performance; outcomes may vary with model/configuration changes, so evidence must record versions and settings.
- Isolation, validation, authorization, and redaction still require implementation and tests. Local inference and synthetic data alone do not establish security.
- Synthetic scenarios demonstrate specific controls and detections; they do not prove production readiness or production AI security/SOC experience.

## Validation plan

Test allowed and denied actions, identity spoofing, cross-user record access, malformed tool arguments, prompt-injection attempts, and execution limits. Verify service bindings and filesystem/network restrictions. Test telemetry redaction and safe encoding with adversarial strings. After separate approval, verify Wazuh collection and detection using synthetic events, including negative cases. Record exact commands, versions, expected versus observed outcomes, and sanitized evidence; do not claim results before execution.

## Decisions requiring owner review

1. Choose the authentication mechanism, authorization policy, synthetic roles, resource ownership rules, and initial read-only tool contracts.
2. Choose service/container topology, network restrictions beyond the initial `127.0.0.1` binding, and execution/resource limits.
3. Approve any dependency/model downloads or other external operations individually; the installed baseline does not authorize new downloads.
4. Choose the Wazuh target, collector, event transport, credentials handling, retention, and detection scope; approve concrete integration/configuration changes separately.
5. Define which sanitized evidence may be published and review it before any approved GitHub push.
