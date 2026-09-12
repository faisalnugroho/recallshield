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
jurisdiction, category) plus authoritative public recall sources. A
consensus-backed `verify_case` run has GenLayer validators independently
fetch each source and extract labeled facts; the contract then derives —
deterministically, never by LLM fiat — a conservative recall status:

- `RECALLED` — exact or explicit family match, authoritative source only
- `PARTIAL_MATCH` — manufacturer-related evidence, applicability not established
- `NO_RECALL_FOUND` — authoritative source inspected, no recall present
- `INCONCLUSIVE` — evidence exists but not authoritative / not recall content
- `SOURCE_UNAVAILABLE` — source unreachable; asserts nothing (no invented status)

Key design: the LLM supplies *labeled facts* (reachability, authority class,
affected models, recall language); the verdict is a pure deterministic
function of those facts (`_derive_source_result`), with an authority gate
(media/industry can never yield RECALLED or NO_RECALL_FOUND) and model
grounding (a claimed model match without a supporting verbatim affected-model
string is demoted). History is append-only: every verification is versioned
(`rsXXXXXX-vNNN`) and can never overwrite a prior result.

## Evidence

- Test suite: 59 direct-mode tests (units, consensus, security, 12 adversarial audits) — CI green, lint clean
- Live Studionet verification: 7 cases, 11 consensus verifications, all recorded in `docs/deployment_log.json`

### Live verification runs

- **CASE1-positive** (rs000001) — final status `RECALLED` (expected `RECALLED`), match `EXACT`, reason `EXACT_PRODUCT_MATCH`
- **CASE2-negative** (rs000002) — final status `NO_RECALL_FOUND` (expected `NO_RECALL_FOUND`), match `NONE`, reason `NO_RECALL_PRESENT`
- **CASE3-authority** (rs000003) — final status `INCONCLUSIVE` (expected `INCONCLUSIVE`), match `NONE`, reason `SOURCE_NOT_RECALL_EVIDENCE`
- **CASE4-partial** (rs000004) — final status `PARTIAL_MATCH` (expected `PARTIAL_MATCH`), match `PARTIAL`, reason `RELATED_ONLY`
- **CASE5-recovery** (rs000005) — final status `SOURCE_UNAVAILABLE` (expected `SOURCE_UNAVAILABLE`), match `NONE`, reason `ALL_SOURCES_UNAVAILABLE`
- **V1-realworld** (rs000006) — final status `SOURCE_UNAVAILABLE` (expected `RECALLED`), match `NONE`, reason `ALL_SOURCES_UNAVAILABLE`
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
site). The contract correctly returned `SOURCE_UNAVAILABLE` with
`ALL_SOURCES_UNAVAILABLE` — exactly the intended conservative behavior: when
evidence is inaccessible, the contract asserts nothing. Recorded as-is, never
silently dropped (append-only history).

### V2 probe — live real-world RECALLED on dewalt.com

V2 registered DEWALT drill model DWD110 (a real 2019 recall) against DEWALT's
live official recall page (HTTP 200 pre-verified). Consensus of validators
fetched the live page and the contract returned `RECALLED` via
`EXACT_PRODUCT_MATCH` — manufacturer match, model DWD110 explicitly in the
affected list, authority class MANUFACTURER. Verification `rs000007-v001`,
tx `0x0124ca8257ce0d90e32119df9d038d4174cda6ce7951b3398f6c8cfd9ae9f0b0`.

## Contract interface

- `create_case(manufacturer, product_name, model_number, product_identifier, jurisdiction, category, source_urls, source_labels)` → case id `rsXXXXXX`
- `verify_case(case_id)` → append-only verification `rsXXXXXX-vNNN` (consensus run)
- Views: `get_case`, `get_verification`, `get_case_history`, `get_stats`

## Notes for reviewers

- Early identical deployment from a crashed harness exists at `0x68976429630cA6BAeF829D96ef90C83eaEf5623B` (same commit, harness died mid-run) — NOT the submission candidate; reported for transparency.
- The dead-page V1 outcome demonstrates the uncertainty path working on a real site, not a fixture.
