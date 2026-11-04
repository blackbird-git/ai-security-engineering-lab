# Investigation 001: Ollama generation truncation

- Recorded: November 4, 2026
- Status: Client validation corrected; instruct model direct API and Python-client results owner-verified
- Related decision: [ADR-0002](../security-decisions/ADR-0002-local-ollama-client.md), Accepted

## Observed failure

The owner reported the following results from the first live Ollama integration test:

| Field | Observed value |
| --- | --- |
| Model | `qwen3:4b` |
| `done` | `true` |
| `done_reason` | `"length"` |
| Response length | 587 characters |
| Content observation | Incomplete reasoning-like text |
| Client outcome | Incorrectly accepted as successful |

This record summarizes the supplied observation; it omits the original prompt and incomplete model text. No live request was made during the corrective task. The configured client sends `think: false` and `options.num_predict: 128`; those settings remain unchanged.

## Analysis and corrective action

The original client checked that `done` was exactly `true` but did not check `done_reason`. A finished generation request can therefore pass validation even when its completion reason indicates a length limit. That missing validation explains the erroneous acceptance. The underlying cause of the reasoning-like text, the model's handling of `think: false`, and whether another token budget would produce a suitable answer remain unverified.

The client now requires both `done is True` and `done_reason == "stop"` before returning text. Missing, invalid, and all non-stop reasons raise the fixed message `Ollama returned an invalid completion.` through `OllamaClientError`. Errors contain no generated text, prompt, or response metadata. Existing JSON, field, HTTP, transport, timeout, and size validations remain in place. The initial validation correction changed no FastAPI endpoints, dependencies, model selection, or token limits; the subsequent model change is recorded below.

## Model comparison and subsequent selection

The owner subsequently supplied a verified direct Ollama API result for the instruct variant. These are live observations reported by the owner, separate from mock-based client tests; no live requests were made during this update.

| Observation | Retained experimental thinking model | Selected normal inference model |
| --- | --- | --- |
| Model | `qwen3:4b` | `qwen3:4b-instruct` |
| `done` | `true` | `true` |
| `done_reason` | `"length"` | `"stop"` |
| Output | 587 characters of incomplete reasoning-like text | `LAB_READY` |
| Assessment | Unsuitable for the initial normal-operation workflow under the tested configuration | Successful direct API completion for this test |

The client now fixes the model to `qwen3:4b-instruct`. The thinking variant remains available for experimental use outside this fixed-model client; there is no caller-selectable model or automatic fallback. The token limit remains 128 and all other security controls are preserved. This comparison is limited to the reported observations, not a controlled benchmark or evidence of reliable behavior across prompts. Instruction-following does not establish trustworthiness or permission to execute model text.

The owner later verified that the corrected client rejected incomplete generation with `Ollama returned an invalid completion.` and that the updated Python `OllamaClient` returned `LAB_READY`. See the [Milestone 3 validation record](../validation/milestone-03-ollama-integration.md) for the separate automated and manually observed live evidence. These results were not rerun during documentation preparation.

## Regression verification

Mock-only tests reproduce `done: true`, `done_reason: "length"`, and a synthetic 587-character response and verify rejection. Additional cases cover successful stop completion, missing completion reason, invalid types, unexpected strings, and sanitized errors. Existing fixtures now include `done_reason: "stop"` where needed so tests of other controls continue to reach the intended validation branch. No tests contact live Ollama.

Run from the repository root:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
git diff --check
```

Observed during this corrective task: 73 client tests passed inside the sandbox. The full suite passed all 85 tests in 0.30 seconds outside the sandbox, with one existing Starlette/HTTPX deprecation warning. `pip check` reported no broken requirements, and `git diff --check` passed. These are automated mock-based results, not live Ollama revalidation.

## Remaining limitations

- The instruct variant passed the owner-reported direct API and updated Python-client tests. Do not generalize these `LAB_READY` results to other prompts or claim comprehensive integration coverage.
- `done_reason: "stop"` is untrusted service metadata and does not prove semantic completeness, truth, safety, or authorization. Returned content remains untrusted text.
- The unchanged 128-token limit may still cause generation failures; the client now rejects length-limited completions instead of returning them as successes.
- The per-read timeout is not a total request deadline, and loopback HTTP does not authenticate the local service.
- The sandbox TestClient hang and existing Starlette/HTTPX deprecation warning are separate unresolved observations.
