#!/usr/bin/env python3
"""RecallShield V1 follow-up probe (LIVE site, no redeploy).

The original V1 probe (case rs000006) pointed at
stanleytools.com/.../stht51454-hammer, which 308-redirects to a
404 — the live page no longer exists. The contract behaved
CORRECTLY and conservatively: SOURCE_UNAVAILABLE, nothing
invented. That run stays in history (append-only by design).

V2 probes a genuinely live manufacturer recall page that exists
today: DEWALT's official safety recall notice for Model DWD110
(a real 2019 recall, page live at dewalt.com, HTTP 200).

Expected: RECALLED via EXACT_PRODUCT_MATCH (manufacturer page,
model DWD110 explicitly affected, authority = MANUFACTURER —
an AUTHORITATIVE class).
"""
import json
import sys
import time
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import ExecutionResult, TransactionStatus

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "docs" / "deployment_log.json"

addr = "0xA58D33605865a096eEAE999F4591fC78Fc021B1f"

URL_DWALT_LIVE = ("https://www.dewalt.com/en-us/support/"
                  "safety-notices-and-recalls/"
                  "2019-dewalt-model-dwd110-and-dwd112")

kd = json.loads((Path(__file__).parent / ".deployer.json").read_text())
account = create_account(account_private_key=kd["private_key"])
print("deployer (saved):", account.address)
client = create_client(chain=studionet, account=account)
client.fund_account(account.address, 10**18)
print("network: studionet", studionet)


def wait_final(tx_hash, what, timeout_s=900):
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
            last_err = e
        time.sleep(5)
    print(f"TIMEOUT waiting for {what}: {tx_hash} last_err={last_err}")
    sys.exit(1)


def check_ok(receipt, what):
    vote = (receipt.get("consensus_data", {})
            .get("leader_receipt", [{}])[0].get("result"))
    exec_name = receipt.get("tx_execution_result_name")
    votes = receipt.get("consensus_data", {}).get("votes", {})
    print(f"  [{what}] vote={vote} exec={exec_name} "
          f"votes={json.dumps(votes)[:140]}")
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
    import re as _re
    m = _re.search(r"rs\d{6}", json.dumps(receipt))
    return tx, (m.group(0) if m else "?")


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
    status = rec["status"]
    verdict = "OK" if status == expect_status else \
        f"MISMATCH (expected {expect_status})"
    print(f"  {what}: status={status} match={rec['match_type']} "
          f"reason={rec['reason_code']} -> {verdict}")
    return {"step": what, "tx": tx, "case_id": case_id, "vid": vid,
            "status": status, "expected": expect_status,
            "match_type": rec["match_type"],
            "reason_code": rec["reason_code"],
            "authority_class": rec["authority_class"],
            "manufacturer_match": rec["manufacturer_match"],
            "model_match": rec["model_match"],
            "recall_reference": rec["recall_reference"],
            "recall_date": rec.get("recall_date", ""),
            "evidence_fingerprint": rec["evidence_fingerprint"],
            "source_results": rec["source_results"]}


print("\n[V2] real-world probe: dewalt.com DWD110 recall page (LIVE, "
      "HTTP 200 verified before this run)")
tx, cid = create_case(
    "v2", "DEWALT", "3/8-inch VSR Drill", "DWD110", "885911037518",
    URL_DWALT_LIVE, "manufacturer safety recall notice")
r = verify_case("V2-realworld", cid, "RECALLED")
r["note"] = ("real-world live site (dewalt.com official recall notice "
             "for DWD110/DWD112, recall dated 2019-01-10, done in "
             "cooperation with US CPSC). Supersedes V1 probe whose "
             "target page 404s; V1 outcome SOURCE_UNAVAILABLE was "
             "CORRECT conservative behavior and remains in history.")

log = json.loads(LOG.read_text())
log.setdefault("runs", []).append(r)
stats = json.loads(client.read_contract(
    address=addr, function_name="get_stats", args=[]))
print("  stats:", stats)
log["stats"] = stats
log["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
log["all_expected_met"] = all(
    x["status"] == x["expected"] for x in log["runs"] if "expected" in x)
LOG.write_text(json.dumps(log, indent=2))
print(f"log updated: {LOG}")
print("V2 done:", r["status"])
