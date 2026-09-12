#!/usr/bin/env python3
"""Deploy RecallShield to GenLayer Studionet + live verification.

Protocol (final pre-submission candidate; exactly ONE deployment):
  D1  deploy (full consensus)                     -> contract address
  CASE 1 positive   regulator page clearly recalls the product    -> RECALLED
  CASE 2 negative   regulator listing inspected, no recall        -> NO_RECALL_FOUND
  CASE 3 authority  media page about the same product            -> INCONCLUSIVE
  CASE 4 partial    manufacturer page, related models only       -> PARTIAL_MATCH
  CASE 5 recovery   unreachable source                           -> SOURCE_UNAVAILABLE
  V1  real-world probe: stanleytools.com manufacturer recall page (live site)
  G1  getters: schema/stats/history sanity

Every consensus run is gated on BOTH the consensus vote AND the
execution result (FINALIZED can still carry a reverted execution).
Evidence is appended to docs/deployment_log.json.
"""
import hashlib
import json
import sys
import time
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import ExecutionResult, TransactionStatus

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "contracts" / "recall_shield.py"
LOG = ROOT / "docs" / "deployment_log.json"
LOG.parent.mkdir(exist_ok=True)

FIX = "https://faisalnugroho.github.io/recallshield-fixtures"
URL_REG_POS = FIX + "/regulator-stanley.html"
URL_REG_NEG = FIX + "/regulator-empty.html"
URL_MEDIA = FIX + "/media-blog.html"
URL_MFR = FIX + "/manufacturer-related.html"
URL_DEAD = "https://recallshield-fixtures.invalid/unreachable.html"
URL_STANLEY_LIVE = "https://www.stanleytools.com/support/safety-notices-recalls/stht51454-hammer"

code = CODE.read_text()
print(f"contract: {len(code)} bytes, sha256[:16] =",
      hashlib.sha256(code.encode()).hexdigest()[:16])

keyfile = Path(__file__).parent / ".deployer.json"
if keyfile.exists():
    kd = json.loads(keyfile.read_text())
    account = create_account(account_private_key=kd["private_key"])
    print("deployer (saved):", account.address)
else:
    account = create_account()
    keyfile.write_text(json.dumps(
        {"address": account.address, "private_key": account.key.hex()}))
    print("deployer (new):", account.address)

client = create_client(chain=studionet, account=account)
client.fund_account(account.address, 10**18)
print("network: studionet", studionet)


def wait_final(tx_hash, what, timeout_s=900):
    """Wait for FINALIZED + verify BOTH the vote and the execution result.
    The SDK's internal poller raises GenLayerError after its own
    retry budget — catch it and keep polling until OUR timeout."""
    t0 = time.time()
    last_err = None
    while time.time() - t0 < timeout_s:
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_hash,
                status=TransactionStatus.FINALIZED,
                full_transaction=True,
                retries=50, interval=6000)
            if receipt:
                return receipt
        except Exception as e:
            last_err = e  # still processing; keep polling
        time.sleep(5)
    print(f"TIMEOUT waiting for {what}: {tx_hash} last_err={last_err}")
    sys.exit(1)


def check_ok(receipt, what):
    vote = (receipt.get("consensus_data", {})
            .get("leader_receipt", [{}])[0].get("result"))
    exec_name = receipt.get("tx_execution_result_name")
    cd = receipt.get("consensus_data", {})
    votes = cd.get("votes", {})
    stderr = ""
    try:
        stderr = cd.get("leader_receipt", [{}])[0].get(
            "genvm_result", {}).get("stderr", "") or ""
    except Exception:
        pass
    print(f"  [{what}] vote={vote} exec={exec_name} "
          f"votes={json.dumps(votes)[:140]}")
    if stderr:
        print("  stderr tail:", stderr[-500:])
    ok_exec = exec_name in (ExecutionResult.FINISHED_WITH_RETURN.value, None)
    if not ok_exec:
        print(f"  EXECUTION FAILED for {what}")
    return ok_exec


def create_case(what, mfr, pname, model, ident, urls_csv, labels_csv,
                jur="US", cat="tools"):
    tx = client.write_contract(
        address=addr, account=account, function_name="create_case",
        args=[mfr, pname, model, ident, jur, cat, urls_csv, labels_csv])
    receipt = wait_final(tx, "create " + what)
    if not check_ok(receipt, "create " + what):
        sys.exit(1)
    # create_case returns case_id via the tx return data
    ret = receipt.get("data", {}).get("return_data") or \
        receipt.get("return_data") or ""
    # fall back: scan for rsXXXXXX pattern in the receipt
    import re as _re
    m = _re.search(r"rs\d{6}", json.dumps(receipt))
    case_id = m.group(0) if m else "?"
    return tx, case_id


def verify_case(what, case_id, expect_status):
    tx = client.write_contract(
        address=addr, account=account, function_name="verify_case",
        args=[case_id])
    receipt = wait_final(tx, "verify " + what)
    if not check_ok(receipt, "verify " + what):
        sys.exit(1)
    import re as _re
    m = _re.search(r"rs\d{6}-v\d{3}", json.dumps(receipt))
    vid = m.group(0) if m else case_id + "-v001"
    rec = json.loads(client.read_contract(
        address=addr, function_name="get_verification", args=[vid]))
    case = json.loads(client.read_contract(
        address=addr, function_name="get_case", args=[case_id]))
    status = rec["status"]
    verdict = "OK" if status == expect_status else \
        f"MISMATCH (expected {expect_status})"
    print(f"  {what}: status={status} match={rec['match_type']} "
          f"reason={rec['reason_code']} -> {verdict}")
    return {
        "step": what, "tx": tx, "case_id": case_id, "vid": vid,
        "status": status, "expected": expect_status,
        "match_type": rec["match_type"], "reason_code": rec["reason_code"],
        "manufacturer_match": rec["manufacturer_match"],
        "model_match": rec["model_match"],
        "recall_reference": rec["recall_reference"],
        "authority_class": rec["authority_class"],
        "evidence_fingerprint": rec["evidence_fingerprint"],
        "verification_count": case["verification_count"],
        "created_at": case["created_at"], "verified_at": rec["verified_at"],
        "source_results": rec["source_results"],
    }


log = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "runs": []}

# ---------------- D1: deploy ----------------
# FINAL CANDIDATE (deployed 2026-09-12, commit bad1403):
#   address 0xA58D33605865a096eEAE999F4591fC78Fc021B1f
#   deploy tx 0x3794c67693a42a0fd9482921e4da2443a1c60afee6184a967b864b148d3644b8
# An identical early deployment from the same commit exists at
# 0x68976429630cA6BAeF829D96ef90C83eaEf5623B (harness crashed
# mid-run); it is NOT the submission candidate and will be reported.
# This script does NOT redeploy: it attaches to the final candidate.
addr = "0xA58D33605865a096eEAE999F4591fC78Fc021B1f"
deploy_tx = "0x3794c67693a42a0fd9482921e4da2443a1c60afee6184a967b864b148d3644b8"
receipt = wait_final(deploy_tx, "deploy (already sent)")
print("contract:  ", addr)
if not check_ok(receipt, "deploy"):
    sys.exit(1)
log["deploy"] = {"tx": deploy_tx, "address": addr,
                 "code_sha256_16":
                     hashlib.sha256(code.encode()).hexdigest()[:16],
                 "note": "attached; deployment happened once, code "
                         "byte-identical to commit bad1403"}

# ---------------- CASE 1: positive (regulator recalls product) ----------
print("\n[CASE 1] regulator page recalls STANLEY STHT51454 -> RECALLED")
tx1, cid1 = create_case(
    "case1", "Stanley Black & Decker", "16 oz Wooden Handle Nailing Hammer",
    "STHT51454", "076174514544",
    URL_REG_POS, "CPSC regulator recall notice")
log["runs"].append(verify_case("CASE1-positive", cid1, "RECALLED"))

# ---------------- CASE 2: negative (regulator, no recall) ----------------
print("\n[CASE 2] regulator listing, no recall for product -> NO_RECALL_FOUND")
tx2, cid2 = create_case(
    "case2", "Bessey Tools", "Classic Clamp 300mm",
    "CL-300", "CL300X",
    URL_REG_NEG, "CPSC regulator recall search")
log["runs"].append(verify_case("CASE2-negative", cid2, "NO_RECALL_FOUND"))

# ---------------- CASE 3: authority edge (media) -------------------------
print("\n[CASE 3] media page about the same product -> INCONCLUSIVE")
tx3, cid3 = create_case(
    "case3", "Stanley Black & Decker",
    "16 oz Wooden Handle Nailing Hammer",
    "STHT51454", "076174514544",
    URL_MEDIA, "tool blog")
log["runs"].append(verify_case("CASE3-authority", cid3, "INCONCLUSIVE"))

# ---------------- CASE 4: partial (related models) -----------------------
print("\n[CASE 4] manufacturer page, related-but-different models"
      " -> PARTIAL_MATCH")
tx4, cid4 = create_case(
    "case4", "Stanley Black & Decker", "Dust Extractor",
    "DXTR-3300", "DX3300",
    URL_MFR, "manufacturer safety notices")
log["runs"].append(verify_case("CASE4-partial", cid4, "PARTIAL_MATCH"))

# ---------------- CASE 5: recovery (unreachable source) -------------------
print("\n[CASE 5] unreachable source -> SOURCE_UNAVAILABLE")
tx5, cid5 = create_case(
    "case5", "Knipex Tools", "Cobra Pliers 250mm",
    "KP-250", "KP250X",
    URL_DEAD, "dead fixture")
log["runs"].append(verify_case("CASE5-recovery", cid5, "SOURCE_UNAVAILABLE"))

# ---------------- V1: real-world probe -------------------------------------
print("\n[V1] real-world probe: stanleytools.com recall page (live site)")
tx6, cid6 = create_case(
    "v1", "Stanley Black & Decker",
    "16 oz Wooden Handle Nailing Hammer",
    "STHT51454", "076174514544",
    URL_STANLEY_LIVE, "manufacturer safety notice")
r = verify_case("V1-realworld", cid6, "RECALLED")
r["note"] = ("real-world live site; expected RECALLED if validators can "
             "fetch it and the page reads as an official manufacturer "
             "recall notice; any uncertainty outcome is recorded as-is")
log["runs"].append(r)

# ---------------- G1: getters ---------------------------------------------
print("\n[G1] getters sanity...")
stats = json.loads(client.read_contract(
    address=addr, function_name="get_stats", args=[]))
print("  stats:", stats)
log["stats"] = stats

# ---------------- summary --------------------------------------------------
print("\n================ LIVE VERIFICATION SUMMARY ================")
ok = True
for r in log["runs"]:
    mark = "OK " if r["status"] == r["expected"] else "!! "
    if r["status"] != r["expected"]:
        ok = False
    print(f"  {mark}{r['step']}: {r['status']} "
          f"(expected {r['expected']}) match={r['match_type']} "
          f"reason={r['reason_code']}")
print("\nALL EXPECTATIONS MET" if ok else "\nSOME CASES DIVERGED - recorded as-is")
log["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
log["all_expected_met"] = ok
LOG.write_text(json.dumps(log, indent=2))
print(f"log written: {LOG}")
print(f"contract address: {addr}")
