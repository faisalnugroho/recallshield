# RecallShield — GenLayer Portal Submission Draft

**Contract**: RecallShield — Consensus Product Recall Oracle
**Repository**: https://github.com/faisalnugroho/recallshield
**Category**: Intelligent Contract (GenLayer Portal)
**Studionet address**: `0xA58D33605865a096eEAE999F4591fC78Fc021B1f`
**Deploy tx**: `0x3794c67693a42a0fd9482921e4da2443a1c60afee6184a967b864b148d3644b8`
**Code sha256[:16]**: `35a27e1a27c1d8c4` (byte-identical to commit `bad1403`; evidence & probes committed up to `bc068b4`)
**Deployer**: `0x67680322F3D06207961a3818dDAcBA6Caf329E0D`

## What it does

RecallShield is a decentralized product-recall verification oracle. A caller
registers a product identity (manufacturer, name, model, identifier,
jurisdiction, category) together with 1–3 public recall source URLs they
designate as authoritative, plus free-text labels for context. A
consensus-backed `verify_case` run has GenLayer validators independently
fetch each source and extract labeled facts; the contract then derives —
deterministically, never by LLM fiat — a conservative recall status:

- `RECALLED` — exact or explicit family match, from an authoritative source class only
- `PARTIAL_MATCH` — manufacturer-related evidence, applicability not established
- `NO_RECALL_FOUND` — an authoritative recall listing was inspected and does not identify the product as recalled (an observation about the inspected source, never a safety guarantee)
- `INCONCLUSIVE` — evidence exists but a safe classification cannot be derived
- `SOURCE_UNAVAILABLE` — sources could not be reliably retrieved; asserts nothing about recall state

### Trust model

- The verdict is a pure deterministic function (`_derive_source_result`) of
  the labeled facts the LLM extracted. The LLM never picks the outcome.
- **Authority is determined by the inspected evidence, not by the caller.**
  Caller-supplied source labels are metadata/context only; they do not
  themselves establish source authority. Validators classify the
  `authority_class` of each page (REGULATOR / MANUFACTURER / INDUSTRY /
  MEDIA / UNKNOWN) from the inspected content, and only the extracted
  class participates in the verdict.
- **Non-authoritative sources cannot produce a persisted definitive recall
  or no-recall classification; they are conservatively demoted to
  INCONCLUSIVE.** A `RECALLED` or `NO_RECALL_FOUND` result can only rest
  on a source whose inspected content classifies as REGULATOR or
  MANUFACTURER — in either direction.
- **Model grounding**: an EXACT match requires the claimed matched model to
  deterministically appear in the extracted affected-model list. A claimed
  match without supporting verbatim text is demoted to `PARTIAL_MATCH`.
- **Evidence fingerprint binding**: each persisted verification binds a
  Keccak-256 (GenVM std-lib) fingerprint over the canonical evidence, tying
  the decision to the exact material it was derived from.
- **Immutable product identity**: identity fields are set once at
  `create_case`; no update method exists.
- **Append-only verification history**: every verification is versioned
  (`rsXXXXXX-vNNN`) and can never overwrite or rewrite a prior result.
- **Independent validator re-fetch and re-derive**: every validator
  retrieves the sources itself and re-derives the decision; consensus
  compares canonical decision fields and the evidence fingerprint — never
  prose, wording, dates, excerpts, or timestamps.

### Scope and limitations

RecallShield answers one narrowly defined technical question: whether the
independently inspected public evidence identifies the registered product
identity as recalled. It is **not** a legal authority and asserts no legal
conclusion; it is **not** a safety certification; it does not claim
universal recall coverage (it can only inspect the caller-designated
sources); and it does not guarantee the accuracy or correctness of external
websites — it reports what the inspected evidence supports, no more. When
evidence is missing, unreachable, non-authoritative, contradictory, or
ambiguous, it returns an explicit uncertainty state; absence of accessible
evidence is never treated as evidence of no recall.

## Evidence

- Test suite: **75 direct-mode tests** (units, consensus, security, and 16 adversarial audit tests) — locally re-run after the documentation changes: 75 passed; CI on latest main: green
- Lint: `genvm-lint check` — **3 checks pass, validation passed** (locally re-run and CI-confirmed; 0 errors)
- Live Studionet verification: **7 cases, 11 consensus verifications**, all recorded in `docs/deployment_log.json`

### Live verification runs

- **CASE1-positive** (rs000001) — final status `RECALLED` (expected `RECALLED`), match `EXACT`, reason `EXACT_PRODUCT_MATCH`
- **CASE2-negative** (rs000002) — final status `NO_RECALL_FOUND` (expected `NO_RECALL_FOUND`), match `NONE`, reason `NO_RECALL_PRESENT`
- **CASE3-authority** (rs000003) — final status `INCONCLUSIVE` (expected `INCONCLUSIVE`), match `NONE`, reason `SOURCE_NOT_RECALL_EVIDENCE`
- **CASE4-partial** (rs000004) — final status `PARTIAL_MATCH` (expected `PARTIAL_MATCH`), match `PARTIAL`, reason `RELATED_ONLY`
- **CASE5-recovery** (rs000005) — final status `SOURCE_UNAVAILABLE` (expected `SOURCE_UNAVAILABLE`), match `NONE`, reason `ALL_SOURCES_UNAVAILABLE`
- **V1-realworld** (rs000006) — final status `SOURCE_UNAVAILABLE` (probe hypothesis `RECALLED` was conditional on the page being live), match `NONE`, reason `ALL_SOURCES_UNAVAILABLE` — conservative-correct: the target page is dead, so the contract asserted nothing
- **V2-realworld** (rs000007) — final status `RECALLED` (expected `RECALLED`), match `EXACT`, reason `EXACT_PRODUCT_MATCH`

### Transaction hashes (verify runs)

| Step | Case | Verification | Verify tx |
|---|---|---|---|
| CASE1-positive | rs000001 | rs000001-v002 | `0x23e8b9aaa5c9c0577c8fe3284458c150fd9c9a2c415f7ac799dd200b0f93c3d4` |
| CASE2-negative | rs000002 | rs000002-v002 | `0x862710be5fe25054f7760c8c8998ee12e2b82a71f307469eb085b24b80951336` |
| CASE3-authority | rs000003 | rs000003-v002 | `0xe710d10894ba3d52efa3a471728afeeeee5d2db5f5ce02206238bec22d975cdf` |
| CASE4-partial | rs000004 | rs000004-v002 | `0xae1492abc7b85beaa10911bc559d4a9dc7437b84efe0fd7923c7b9aaa8d6c4fa` |
| CASE5-recovery | rs000005 | rs000005-v001 | `0x2640bd92a8576b9aaf7f72d466ff87ad00f4cf3996652dfacad55d9b4807907a` |
| V1-realworld | rs000006 | rs000006-v001 | `0x3ccdd223bf96e4f321652806917e0a8854697c0cdb93cf95a5928cd8c0e307c2` |
| V2-realworld | rs000007 | rs000007-v001 | `0x0124ca8257ce0d90e32119df9d038d4174cda6ce7951b3398f6c8cfd9ae9f0b0` |

Deploy tx `0x3794c67693a42a0fd9482921e4da2443a1c60afee6184a967b864b148d3644b8`.

### V1 probe — conservative-correct behavior on a dead URL

The first real-world probe (V1) targeted stanleytools.com's recall page for
STHT51454; that URL now 308-redirects to a 404 (page removed from the live
site, independently verified before V2 was prepared). The contract
correctly returned `SOURCE_UNAVAILABLE` with `ALL_SOURCES_UNAVAILABLE` —
exactly the intended conservative behavior: when evidence is inaccessible,
the contract asserts nothing about recall state. Recorded as-is, never
silently dropped (append-only history).

### V2 probe — live real-world RECALLED on dewalt.com

V2 registered DEWALT drill model DWD110 (a real 2019 recall) against
DEWALT's live official recall page for models DWD110/DWD112 (HTTP 200
pre-verified). Consensus of validators independently fetched the live page;
the inspected content classified as MANUFACTURER authority and explicitly
lists DWD110 as affected, and the contract returned `RECALLED` via
`EXACT_PRODUCT_MATCH`. Verification `rs000007-v001`, tx
`0x0124ca8257ce0d90e32119df9d038d4174cda6ce7951b3398f6c8cfd9ae9f0b0`.

## Contract interface

- `create_case(manufacturer, product_name, model_number, product_identifier, jurisdiction, category, source_urls_csv, authority_labels_csv)` — write; registers an immutable product identity + 1–3 public sources (idempotent by identity fingerprint)
- `verify_case(case_id)` — write; consensus-backed verification, returns verification id
- `reverify_case(case_id)` — write; fresh verification of an already-verified case
- Views: `get_case`, `get_case_by_fingerprint`, `get_verification`, `get_verification_history`, `get_stats`

## Notes for reviewers

- Early identical deployment from a crashed harness exists at `0x68976429630cA6BAeF829D96ef90C83eaEf5623B` (same commit, harness died mid-run) — NOT the submission candidate; reported for transparency.
- The dead-page V1 outcome demonstrates the uncertainty path working on a real production site, not a fixture.

**Status: READY FOR MANUAL PORTAL SUBMISSION**
