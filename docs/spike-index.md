# Spike and Evaluation Index

Every document (or self-contained section) in this repository that records a
spike, evaluation, or exploratory report, with its current status. Added by
issue #1424 so a reader never has to infer from prose whether a spike's
conclusion still holds, was superseded, or is still open.

Each listed document carries the same marker directly under its title (or
section heading):

```text
> **Spike status:** `<status>` · **Last reviewed:** <date> · **Index:** spike-index.md
>
> **Outcome:** <what happened, with links>
```

## Status vocabulary

| Status | Meaning | Required in the marker |
|---|---|---|
| `concluded-adopted` | The recommendation was implemented or is the standing decision. | Where it was implemented or decided. |
| `concluded-rejected` | The option was evaluated and deliberately not taken. | The reason. |
| `superseded` | A later decision, ADR, or implementation replaced the conclusion. | A link to what superseded it. |
| `still-open` | Still relevant; work is deferred or waiting on a trigger. | A tracked issue (`Tracked in: #N`), or `Tracked in: pending` with a draft under [open items](#open-items-awaiting-a-tracking-issue) until one is filed. |
| `abandoned` | Dropped without a recorded conclusion. | The best-available reason. |

A spike whose recommendation was partly adopted and partly deferred is marked
by its open part (`still-open`), and the marker names what was adopted or
superseded.

## Index

| Document | Topic | Status | Resolution |
|---|---|---|---|
| [SPIKE_LIVE_INGESTION_EVALUATION.md](SPIKE_LIVE_INGESTION_EVALUATION.md) | Live RPC/Horizon ingestion for replay (#933) | `concluded-adopted` | Snapshot-then-Replay: `scripts/fetch_testnet_snapshot.py`, [tools/replay/README.md](../tools/replay/README.md) |
| [reports/aggregator-cross-shard-reconciliation-spike.md](reports/aggregator-cross-shard-reconciliation-spike.md) | Aggregator cross-shard reconciliation | `concluded-adopted` | Cited by [ADR: aggregator score responsibilities](adr/aggregator-score-responsibilities.md) |
| [risk-score-schema-generation.md](risk-score-schema-generation.md) | `RiskScore` cross-repo schema generation (#932) | `concluded-adopted` | `tools/schema-gen` |
| [mutation-testing.md](mutation-testing.md) | Expanding `cargo-mutants` scope (#935) | `concluded-adopted` | `.cargo/mutants.toml`, `.github/workflows/mutation.yml` |
| [rent-griefing-analysis.md](rent-griefing-analysis.md) | Rent griefing via high-cardinality wallets | `concluded-adopted` | Existing bound kept; keeper reward in `rent_relay_credits.rs` |
| [oss-fuzz-evaluation.md](oss-fuzz-evaluation.md) | OSS-Fuzz onboarding (#1232) | `still-open` | Harnesses adopted; ClusterFuzzLite step superseded by [nightly-fuzzing.md](nightly-fuzzing.md); OSS-Fuzz application tracking issue pending ([open items](#open-items-awaiting-a-tracking-issue)) |
| [reproducible-builds.md § wasm-opt evaluation](reproducible-builds.md#post-processing-with-wasm-opt-evaluation) | `wasm-opt` pass pipeline (#1194) | `still-open` | Methodology only, no data recorded; tracking issue pending ([open items](#open-items-awaiting-a-tracking-issue)) |
| [zk-range-proofs.md § ZKML feasibility](zk-range-proofs.md#feasibility-spike-verifying-zkml-inference-proofs-on-soroban-1189) | ZKML inference proofs (#1189) | `still-open` | Gated on pairing host functions; tracking issue pending ([open items](#open-items-awaiting-a-tracking-issue)) |
| [attestation-spec.md § 6](attestation-spec.md#6-post-quantum-attestation-feasibility-spike-1178) | Post-quantum attestation (#1178) | `still-open` | Monitor with revisit triggers; tracking issue pending ([open items](#open-items-awaiting-a-tracking-issue)) |

## Open items awaiting a tracking issue

These `still-open` spikes are still relevant but have no tracking issue yet.
Each line is a ready-to-file issue title and scope. Once it is filed, replace
`pending` in the document's marker and in its index row with the issue number.

| Spike | Draft issue title | Scope |
|---|---|---|
| [oss-fuzz-evaluation.md](oss-fuzz-evaluation.md) | Apply to OSS-Fuzz once the contract has mainnet integrators | Re-check the acceptance bar, add the SECURITY.md disclosure line, submit `fuzz/oss-fuzz/`. Trigger: first mainnet integrator. |
| [reproducible-builds.md § wasm-opt evaluation](reproducible-builds.md#post-processing-with-wasm-opt-evaluation) | Fill in the wasm-opt evaluation report and record the decision | Run the methodology against each candidate (including the `stellar contract optimize` output the release already ships), fill the table, adopt or record the rejection in an ADR. |
| [zk-range-proofs.md § ZKML feasibility](zk-range-proofs.md#feasibility-spike-verifying-zkml-inference-proofs-on-soroban-1189) | Re-evaluate ZKML inference verification when pairing host functions are available | Prerequisite 1 of the spike: confirm `bn254`/`bls12-381` availability and cost on the target network and SDK. |
| [attestation-spec.md § 6](attestation-spec.md#6-post-quantum-attestation-feasibility-spike-1178) | Monitor post-quantum attestation revisit triggers | Check the § 6.4 triggers (Soroban CPU budget, PQ signature standardisation, variable-length `set_service_pubkey`) each release. |

### Reviewed and not listed

These read like reports but are not spikes: they audit or record a fixed
artefact rather than explore an open question, so they carry no spike status.

- Audits: [audit-constant-time-2026-07-20.md](audit-constant-time-2026-07-20.md),
  [zk-range-proof-audit.md](zk-range-proof-audit.md),
  [cross-contract-authorization-audit.md](cross-contract-authorization-audit.md),
  [replay-protection-audit.md](replay-protection-audit.md).
- Generated run reports: [reports/production-readiness-report.md](reports/production-readiness-report.md),
  [reports/testnet-canary-rehearsal.md](reports/testnet-canary-rehearsal.md).
- Decision records: [adr/](adr/) (ADRs are the decisions spikes feed into).

## Keeping this index current

- **New spike.** A PR that adds a spike, evaluation, or exploratory report adds
  the marker and a row here in the same PR.
- **Every release.** The release checklist
  ([release-process.md § Spike status review](release-process.md#spike-status-review))
  asks the release owner to re-check each `still-open` row against its tracking
  issue and against any ADR or implementation merged since the last release,
  update statuses that changed, and bump **Last reviewed**.
- **CI.** `python3 tools/check_spike_index.py` (run by the docs workflow) fails
  when a document carries a spike marker but is missing from this index, when
  the index lists a document that has no marker, when the two statuses differ,
  or when a `still-open` row has neither a tracking issue nor an explicit `pending` entry, or a `superseded` marker links to nothing. `pending` entries are reported as warnings so they stay visible in every docs run.
