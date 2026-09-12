#!/usr/bin/env python3
"""Probe deployment state after harness crash. Read-only."""
import json
from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet

keyfile_json = json.loads(open("/home/ubuntu/recallshield/scripts/.deployer.json").read())
account = create_account(account_private_key=keyfile_json["private_key"])
client = create_client(chain=studionet, account=account)

TX2_DEPLOY = "0x3794c67693a42a0fd9482921e4da2443a1c60afee6184a967b864b148d3644b8"
C_RUN2 = "0xA58D33605865a096eEAE999F4591fC78Fc021B1f"
C_RUN1 = "0x68976429630cA6BAeF829D96ef90C83eaEf5623B"
TX1_CASE1 = "0x35c17476e707438cd819efbf1d5362ea9a8d08456894fda488bf99ff74d1fb89"

for label, txh in (("run2-deploy", TX2_DEPLOY), ("run1-case1", TX1_CASE1)):
    try:
        r = client.get_transaction_receipt(txh)
        print(label, "tx", txh[:18],
              "status:", r.get("status_name"),
              "exec:", r.get("tx_execution_result_name"))
    except Exception as e:
        print(label, "tx", txh[:18], "ERROR:", str(e)[:160])

for label, addr in (("RUN2-contract", C_RUN2), ("RUN1-contract", C_RUN1)):
    try:
        s = client.read_contract(address=addr, function_name="get_stats", args=[])
        print(label, addr, "->", s)
    except Exception as e:
        print(label, addr, "read ERROR:", str(e)[:200])
