# PhantomGate-AI - implementation handover, revision 3.0

Prepared 22 October 2026. Read this together with the PDF report and `PROJECT_SPEC.json`, then inspect the actual supplied code.

## Core idea in one paragraph

Keep the existing Go reverse proxy as the main project. Embed an optional, local, read-only AI assistant that classifies authentication outcomes and technical-failure categories from sanitized proxy event windows. The students train the model. Verify predictions against independent synthetic-application and fault-fixture records in an offline evaluation process. Improve conventional proxy reliability separately. The assistant observes and explains; it never controls routing, targets, payloads, exploitation or authorization.

## Current status and superseded direction

- Delivered: report, diagrams, design contracts, this handover and a machine-readable specification.
- Not delivered: runtime AI modules, new lab fixtures, dataset, trained models, or experimental results.
- Existing baseline: `Un-9oon/PhantomGate`, code commit `8ae8437a4900b03fbaf187ac98bbde6127687efa`.
- The previous report's action-selection policy and next-test agent are superseded. Do not implement that architecture accidentally.
- The framework's historical claims of universal MFA bypass, zero latency and production readiness are not accepted as evidence.
- A candidate research gap has been identified; global novelty has not been established. AI log diagnosis and automated pentesting already exist.

## Before editing

1. Read applicable repository instructions and inspect `git status`.
2. Record the actual code commit; compare with the baseline rather than assuming identical files.
3. Read `internal/proxy/proxy.go`, `internal/config/config.go`, `cmd/phantomgate/main.go` and relevant tests.
4. Inspect platform-specific modules and the available Go toolchain. Run applicable existing checks and record actual results.
5. Preserve unrelated changes. Do not convert this into a generic scanner, detector, or autonomous assessment agent.

## Existing code map

| File / symbol | Verified role | Planned integration |
| --- | --- | --- |
| `internal/proxy/proxy.go`, `PhantomProxy.ServeHTTP` | Main proxy forwarding path | Emit allowlisted metadata using a non-blocking sink; never wait for inference |
| Same file, `proxy.ErrorHandler` closure | Handles forwarding errors | Map observed failures to normalized event codes |
| `internal/config/config.go` | YAML configuration/defaults | Add validated assistant settings and scoped lab configuration |
| `cmd/phantomgate/main.go` | Lifecycle and listeners | Start optional workers, expose degradation, implement bounded shutdown |
| `internal/store/store.go` | Capture-oriented JSON storage | Keep secret capture records out of AI pipeline; use separate evidence storage |
| `internal/api/server.go` | API server and routes | Inspect actual wiring; optionally expose read-only diagnosis views |

Do not assume the API module is wired into the main entry point. File presence is not runtime evidence.

## Proposed new modules

- `internal/telemetry/`: typed allowlisted events, sanitizer, non-blocking sink, loss counters.
- `internal/diagnosis/`: bounded windows, local client, schema validation, deterministic explanation templates.
- `internal/evidence/`: redacted transactional persistence and exports.
- `ai/`: feature extraction, training, calibration, evaluation-compatible inference service.
- `lab/`: synthetic apps, scope manifests, reset/health checks, separate oracle fixtures.
- `evaluation/`: immutable group splits, rule baseline, metrics, privacy checks, overhead and failure tests.

These paths are proposed, not existing implementation claims. Prefer repository conventions after inspection.

## Runtime architecture

```text
Synthetic browser <-> Go reverse proxy <-> Synthetic application
                            |
                 allowlisted metadata only
                            v
               non-blocking bounded event sink
                            v
                 correlated bounded windows
                            v
                 local trained AI service
                            v
              evidence-linked diagnostic records
                            v
                 operator view / run report

Separate research path:
app truth + verified fault records -> oracle labels
frozen predictions + oracle labels -> offline evaluation
```

The runtime model and proxy must have no oracle credentials or read access. Correlation identifiers are grouping keys, never predictive features. The model cannot see scenario or fault-injection IDs.

## Version 1 labels

Two independently scored heads are required:

- Outcome: `COMPLETE`, `REJECTED`, `INCOMPLETE`, `UNKNOWN`.
- Failure: `NONE`, `PROXY`, `UPSTREAM`, `CLIENT`, `UNKNOWN`.

Runtime status is distinct: `PREDICTED`, `ABSTAINED`, `UNAVAILABLE`, `INVALID_INPUT`.

`COMPLETE` means the synthetic application confirms completion of its defined flow, not that a vulnerability or bypass exists. `UNKNOWN` is an oracle ambiguity label. `ABSTAINED` is a model decision to withhold an assertion. A technical fault can coexist with an incomplete flow. Do not merge these heads into one mutually exclusive class without documenting and validating a schema revision.

## Event and window rules

- Construct telemetry by allowlist before enqueueing; do not enqueue raw HTTP request/response objects.
- Exclude bodies, passwords, token/cookie values, authorization headers, raw URLs/query strings, raw error text, user identities and arbitrary header maps.
- Use normalized enums for event kinds, response status classes, technical error categories and content types; bounded size/timing summaries are allowed.
- Use opaque controller-issued run/flow/event IDs and per-flow sequence numbers. Do not hash tokens as identifiers.
- If correlation is ambiguous, record it as unassigned/unknown rather than merging users.
- Bound every queue, event, window, worker pool and retry budget.
- Close on terminal observation, idle timeout, maximum age/event count or cancellation; record closure reason and completeness separately.
- A terminal observation is not oracle ground truth; do not infer authentication success from status 200 alone.
- Track event loss; a saturated queue returns immediately and marks affected windows incomplete.
- Route late events into a linked new window; preserve the earlier prediction and its timestamp.

## Proposed defaults (freeze after pilot)

Assistant disabled; local service `http://127.0.0.1:8765`; queue capacity 10,000; max 256 events/window; max window age 60 s; idle closure 5 s; inference deadline 250 ms; bounded workers; at most one bounded retry outside the forwarding path. Values are design choices, not measured guarantees.

## Model-service contract

`POST /v1/diagnose` accepts schema version, model ID, opaque flow/window IDs, normalized events and completeness flags. It returns the `pg.diagnosis.v1` record defined in `PROJECT_SPEC.json`.

`GET /healthz` returns liveness; `GET /readyz` returns readiness for the pinned artifact/schema. Do not expose raw training data or arbitrary command execution.

Validate field types, sizes, enums, probabilities, evidence-reference membership and model/schema identity. Null confidence is required for unavailable/invalid results. Do not load untrusted executable serialized models. Bind locally or to a restricted service network.

## Output and explanation behavior

Store predicted outcome/failure, status, confidence for each head, abstention reason, model version, window identity and supporting observed event IDs. Version 1 explanations use templates, not unrestricted generated text. A prediction must be displayed as a prediction, never a confirmed vulnerability. Independently verified labels appear separately in research reports.

Model failure: return `UNAVAILABLE`; authorized proxy forwarding continues. Schema error: return `INVALID_INPUT`. Incomplete evidence: use `ABSTAINED` or an explicit incomplete prediction according to validation-frozen rules. Never silently mark an outage as normal or show rule fallback output as model output.

## Ground truth

Use instrumented synthetic application state for outcome labels. Use independently recorded and verified-active fault fixtures for failure provenance. Merely scheduling a fault does not prove causation. Mark ambiguous and multi-fault cases `UNKNOWN` or apply a documented primary-label rule, then report them separately.

For supervised training, join labels only as targets. For evaluation, freeze predictions before joining labels. Store the oracle separately from runtime evidence with separate access permissions.

## Model and evaluation plan

1. Rules and majority baselines before ML.
2. Logistic regression and gradient-boosted trees on window summaries; student-run training.
3. Optional small temporal model only if ordering and sample size justify it.
4. Three independently implemented synthetic apps; app-level holdouts plus grouped scenario families and collection periods.
5. All windows of the same flow, duplicates and configuration family stay in one split.
6. Fit preprocessing on training only. Tune and calibrate on validation only. No test-driven threshold selection.
7. Strong rules get the same useful error codes as ML. A trivial label problem is not evidence that AI is necessary.
8. Report each head, joint correctness, unknowns, abstentions, per-class precision/recall, macro-F1, calibration and risk-versus-coverage.
9. Compare proxy throughput, p50/p95/p99 latency, CPU/RAM and loss rate with assistant off/on at the same workload.
10. If the model does not beat rules, report the null result and benchmark value honestly.

Record actual sample counts, hardware, seeds, dependency versions, data/split/model hashes, annotation guidelines, label reviews, failures and exclusions.

## Implementation milestones

| Milestone | Deliverable | Exit criterion |
| --- | --- | --- |
| M1 | One synthetic fixture + baseline review | Existing forwarding behavior documented |
| M2 | Event schema + sanitizer + sink | Canary removal and non-blocking saturation checks pass |
| M3 | Windows + oracle + rules + evidence store | End-to-end episode with independent label |
| M4 | Pilot dataset + trained models | Reproducible grouped training/validation |
| M5 | Embedded local assistant | Explicit health, abstention and outage behavior |
| M6 | Evaluation + hardening + report | Held-out metrics and actual reliability evidence |

## Acceptance tests

T01 assistant-off forwarding regression; T02 secret-canary exclusion; T03 non-blocking queue saturation; T04 interleaved-flow isolation; T05 oracle leakage prevention; T06 model-outage degradation; T07 valid evidence references; T08 held-out split/duplicate audit; T09 committed-record crash recovery; T10 bounded cancellation/drain.

Add meaningful tests for altered code paths. Do not claim test success from test-file presence. No application, training or reliability checks were run while preparing this document revision.

## Receiving-AI starting instruction

Summarize the scope and unknowns, inspect the actual repository and instructions, then implement M1-M2 before model work. Keep the reverse proxy central. Return a concrete increment with actual validation evidence. Do not promise novelty or production robustness before measurements.
