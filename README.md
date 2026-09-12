# RecallShield — Consensus Product Recall Oracle

A GenLayer Intelligent Contract that answers ONE narrowly-defined
technical question:

> Based on the caller-designated authoritative public source(s), does
> the independently inspected evidence identify this exact product
> identity — or an explicitly matching product family — as recalled?

Anyone may register a product identity together with 1–3 authoritative
public recall source URLs (an official regulator recall database, a
government recall notice, or an official manufacturer recall page).
GenLayer validators then independently retrieve those sources,
extract bounded structured recall facts, and the contract derives a
conservative classification that is persisted on-chain with an
immutable verification history.

**RecallShield is not a legal authority.** It never claims a product
is legally safe or unsafe, and it never invents a recall status: if
evidence is missing, unreachable, non-authoritative, contradictory, or
ambiguous, it returns an explicit uncertainty state — never
`NO_RECALL_FOUND`. Absence of accessible evidence is NOT evidence of
no recall.

## Classification model

| Status | Meaning |
|---|---|
| `RECALLED` | An authoritative source explicitly identifies the exact product identity (EXACT) or an unambiguously covered model family (FAMILY) as recalled. |
| `NO_RECALL_FOUND` | An inspectable, **authoritative** recall listing was examined and does not identify the product as recalled. A positive observation about the inspected source — never a safety guarantee. |
| `PARTIAL_MATCH` | The manufacturer appears in recall evidence but exact applicability is not established. Never auto-promoted to `RECALLED`. |
| `INCONCLUSIVE` | Evidence exists but a safe classification cannot be derived (non-authoritative source, contradiction, incomplete coverage, unusable content, extraction failure). |
| `SOURCE_UNAVAILABLE` | The designated sources could not be reliably retrieved. |

## Architecture (GenLayer-native)

- **Deterministic** — input validation, IDs, counters, case
  fingerprints (Keccak-256 over canonical JSON, GenVM std-lib), status
  transitions, authorization, result persistence, history, views,
  events, timestamps (node-assigned `gl.message_raw` datetime, parsed
  with pure integer math).
- **Non-deterministic (leader/validator boundaries only)** —
  `gl.nondet.web.get` per source URL (capped, HTML-stripped, bounded)
  and `gl.nondet.exec_prompt` fact extraction per source. No storage
  access inside nondeterministic boundaries.
- **Post-consensus** — purely deterministic persistence: enum checks,
  fingerprint binding, immutable history append, latest-result
  pointer, counters, events. No LLM, no web, no reinterpretation.

### The verdict is DERIVED, not asked

The LLM only extracts **labeled facts** from the retrieved page
(reachable, is-recall-content, recall-present, authority class,
manufacturer/models listed, explicit match booleans, reference
number). The contract derives the verdict as a pure function of those
facts:

- EXACT requires manufacturer match **and** a deterministically
  grounded model match (the claimed matched model must literally
  appear in the extracted affected-model list) — hallucinated or
  injection-driven match claims are demoted to `PARTIAL_MATCH`.
- **Authority gate**: any definitive classification — positive
  (`RECALLED`, `PARTIAL_MATCH`) or negative (`NO_RECALL_FOUND`) — may
  only rest on an authoritative source class (regulator /
  manufacturer). Media, industry, or unknown operators demote to
  `INCONCLUSIVE` in EITHER direction.
- **Conservative combination**: unavailability and ambiguity can
  never produce `NO_RECALL_FOUND`; contradictions never resolve.

### Consensus compares substance

Validators independently re-fetch and re-derive everything, then
compare the canonical decision fields — statuses, reason codes,
authority classes, match booleans, RECALLED reference numbers, and a
Keccak-256 evidence fingerprint binding the decision to the exact
canonical evidence. Never compared: prose, wording, dates, excerpts,
timestamps.

### Prompt-injection defense

All retrieved web content is untrusted data. The extraction prompt
carries a fixed security preamble, and deterministic grounding gates
clamp whatever the model claims.

## Immutability boundary

Product identity is set only at creation — no update method exists.
Every stored verification record re-binds the case fingerprint and is
appended, never rewritten. Re-verification cannot mutate history.

## Contract API

| Method | Type | Description |
|---|---|---|
| `create_case(manufacturer, product_name, model_number, product_identifier, jurisdiction, category, source_urls_csv, authority_labels_csv)` | write | Register an immutable product identity + 1–3 authoritative public sources. Idempotent by identity fingerprint. |
| `verify_case(case_id)` | write | Run a consensus-backed verification. Returns `verification_id`. Open to anyone. |
| `reverify_case(case_id)` | write | Fresh verification of an already-verified case (recall info changes over time). |
| `get_case(case_id)` | view | Full case state (identity + latest result). |
| `get_case_by_fingerprint(fp)` | view | case_id for an identity fingerprint. |
| `get_verification(vid)` | view | An immutable verification record. |
| `get_verification_history(case_id)` | view | Last ≤10 verification ids. |
| `get_stats()` | view | Global counters. |

## Testing

```bash
python -m pytest tests/direct/ -q        # 59/59 direct-mode tests
genvm-lint check contracts/recall_shield.py   # 3 checks pass
```

The suite covers: input validation (all fields, jurisdiction
sub-national ISO-3166-2), URL validation (https-only, credentials,
host forms), idempotent creation, the full classification ladder
(EXACT/FAMILY/PARTIAL/NO_RECALL/INCONCLUSIVE/SOURCE_UNAVAILABLE),
authority demotion in both directions, multi-source combination
(contradiction, partial+unavailable, all-unavailable), fetch failures
(non-200, oversize, crash), LLM failures (malformed JSON, wrong
schema, bad types, exception), prompt-injection (grounding demotes
injected match claims), equivalence mechanics (accept on same
substance with different prose, reject on evidence divergence, reject
forged leader payloads), immutability (identity never mutates,
records append-only, bounded history), cross-case isolation, open
authorization audit trail, bounded inputs (affected-models cap,
string caps, unicode), and ledger integrity (counters, ids bound to
case+round, evidence fingerprints).

## License

MIT.
