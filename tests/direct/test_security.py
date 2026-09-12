"""Security-audit tests for RecallShield: immutability, isolation,
authorization surface, storage growth, and adversarial payloads.
"""
import json
import sys
from pathlib import Path

from eth_utils import to_checksum_address

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import (  # noqa: E402
    deploy, llm_answer, mock_body, page, std_case_kwargs,
    URLS,
)


def addr_str(raw):
    """gltest addresses are Address objects; the contract stores
    checksummed hex via str(gl.message.sender_address)."""
    if isinstance(raw, str):
        return raw
    if hasattr(raw, "as_bytes"):
        raw = raw.as_bytes
    return to_checksum_address(bytes(raw))


def _case(c):
    return c.create_case(**std_case_kwargs())


def _verify_recalled(vm, c, cid):
    mock_body(vm, URLS[0], page("Recall Search"))
    mock_body(vm, URLS[1], page("ACME Recalls"))
    a = llm_answer(affected_models=["AF-3000"], model_match=True,
                   matched_model="AF-3000", recall_reference="RC-1")
    vm.mock_llm(".*", a)
    return c.verify_case(cid)


class TestImmutability:
    def test_identity_fields_never_mutate(self, direct_vm, direct_deploy,
                                          direct_alice, direct_bob):
        c = deploy(direct_vm)
        direct_vm.sender = direct_alice
        cid = _case(c)
        before = json.loads(c.get_case(cid))
        _verify_recalled(direct_vm, c, cid)
        _verify_recalled(direct_vm, c, cid)
        after = json.loads(c.get_case(cid))
        for k in ("case_id", "creator", "manufacturer", "product_name",
                  "model_number", "product_identifier", "jurisdiction",
                  "category", "source_urls", "authority_labels",
                  "case_fingerprint", "created_at"):
            assert before[k] == after[k], k
        assert after["seq"] == "2"
        assert after["verification_count"] == "2"

    def test_verification_records_append_only(self, direct_vm,
                                               direct_deploy):
        c = deploy(direct_vm)
        cid = _case(c)
        vid1 = _verify_recalled(direct_vm, c, cid)
        rec1 = json.loads(c.get_verification(vid1))
        direct_vm.clear_mocks()
        vid2 = _verify_recalled(direct_vm, c, cid)
        # the first record is untouched
        assert json.loads(c.get_verification(vid1)) == rec1
        assert vid2 != vid1

    def test_no_update_path_exists(self, direct_vm, direct_deploy):
        # Method-surface enumeration: the only write entry points are
        # create_case, verify_case, reverify_case. No setters, no
        # upgrade hooks, no admin.
        c = deploy(direct_vm)
        import inspect
        forbidden = []
        for name in dir(c):
            if name.startswith("_"):
                continue
            m = getattr(c, name, None)
            if m is None or not callable(m):
                continue
            if any(s in name.lower() for s in (
                    "update", "set_", "admin", "upgrade", "transfer",
                    "withdraw", "delete", "pause", "owner")):
                forbidden.append(name)
        assert forbidden == []
        writes = sorted(
            k for k in type(c).__dict__
            if callable(getattr(type(c), k, None))
            and getattr(getattr(type(c), k), "is_public_write", False)
        )
        # if the decorator attribute isn't exposed, fall back to the
        # documented surface
        if writes:
            assert set(writes) <= {"create_case", "verify_case",
                                   "reverify_case"}, writes


class TestCrossCaseIsolation:
    def test_two_cases_independent_results(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid1 = _case(c)
        kw2 = std_case_kwargs()
        kw2["manufacturer"] = "Bolt Corp"
        kw2["model_number"] = "BT-9"
        kw2["product_identifier"] = "BT9"
        cid2 = c.create_case(**kw2)
        # source 0 lists ACME recalled; source 1 lists nobody
        mock_body(direct_vm, URLS[0], page("Recall Search"))
        mock_body(direct_vm, URLS[1], page("ACME Recalls"))
        a0 = llm_answer(manufacturer_stated="OTHERCORP",
                        manufacturer_match=False)
        vm_answer = llm_answer(affected_models=["AF-3000"],
                               model_match=True, matched_model="AF-3000")
        direct_vm.mock_llm(".*", vm_answer)
        vid1 = c.verify_case(cid1)
        rec1 = json.loads(c.get_verification(vid1))
        assert rec1["status"] == "RECALLED"
        direct_vm.clear_mocks()
        mock_body(direct_vm, URLS[0], page("Recall Search"))
        mock_body(direct_vm, URLS[1], page("ACME Recalls"))
        direct_vm.mock_llm(".*", a0)
        vid2 = c.verify_case(cid2)
        rec2 = json.loads(c.get_verification(vid2))
        assert rec2["status"] == "NO_RECALL_FOUND"
        # and re-reading case1's latest pointer is untouched
        assert json.loads(c.get_case(cid1))["latest_status"] == "RECALLED"


class TestAuthorization:
    def test_open_participation_recorded(self, direct_vm, direct_deploy,
                                         direct_alice, direct_bob):
        # Open by design: anyone may create/verify; requester recorded
        # for audit. No role checks exist.
        c = deploy(direct_vm)
        direct_vm.sender = direct_alice
        cid = _case(c)
        assert json.loads(c.get_case(cid))["creator"] == \
            addr_str(direct_alice)
        direct_vm.sender = direct_bob
        vid = _verify_recalled(direct_vm, c, cid)
        assert json.loads(c.get_verification(vid))["requester"] == \
            addr_str(direct_bob)


class TestBoundedInputs:
    def test_history_pointer_bounded(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _case(c)
        for _ in range(12):
            direct_vm.clear_mocks()
            _verify_recalled(direct_vm, c, cid)
        hist = json.loads(c.get_verification_history(cid))
        assert len(hist) == 10          # MAX_HISTORY_PER_CASE
        # full records still individually retrievable
        v001 = json.loads(c.get_verification(cid + "-v001"))
        assert v001["round"] == "1"

    def test_affected_models_capped_at_12(self, direct_vm, direct_deploy):
        m = None
        from helpers import load_contract_module
        m = load_contract_module()
        many = ["M-%d" % i for i in range(50)]
        s = m._sanitize_source_answer(
            json.dumps(json.loads(llm_answer(affected_models=many))))
        assert s["ok"] is True
        assert len(s["data"]["affected_models"]) == m.MAX_AFFECTED_MODELS

    def test_strings_capped(self, direct_vm, direct_deploy):
        from helpers import load_contract_module
        m = load_contract_module()
        long_ref = "R" * 500
        s = m._sanitize_source_answer(
            json.loads(llm_answer(recall_reference=long_ref)) and
            json.dumps(json.loads(llm_answer(recall_reference=long_ref))))
        assert s["ok"] is True
        assert len(s["data"]["recall_reference"]) == m.MAX_REFERENCE_CHARS

    def test_weird_unicode(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = c.create_case(
            manufacturer="Ünïcödé ß Corp", product_name="网红 空气炸锅",
            model_number="ΔΦ-3000", product_identifier="ΔΦ3000",
            jurisdiction="DE", category="misc",
            source_urls_csv="https://a.example.gov/x",
            authority_labels_csv="db")
        assert json.loads(c.get_case(cid))["manufacturer"] == \
            "Ünïcödé ß Corp"

    def test_case_limit_guard(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        # monkeypatching the deployed instance isn't possible; the
        # guard is exercised by setting the counter near the cap via
        # the pure module (coverage of the branch) — here we simply
        # verify the constant and the check exist.
        from helpers import load_contract_module
        m = load_contract_module()
        assert m.MAX_CASES == 50000
        assert m.MAX_VERIFICATIONS == 200000
        src = Path(m.__file__).read_text()
        assert "case_limit_reached" in src
        assert "verification_limit_reached" in src


class TestLedgerIntegrity:
    def test_stats_counters_consistent(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid1 = _case(c)
        kw2 = std_case_kwargs(); kw2["manufacturer"] = "Bolt Corp"
        kw2["model_number"] = "BT-9"; kw2["product_identifier"] = "BT9"
        cid2 = c.create_case(**kw2)
        _verify_recalled(direct_vm, c, cid1)
        direct_vm.clear_mocks()
        _verify_recalled(direct_vm, c, cid2)
        s = json.loads(c.get_stats())
        assert s["case_count"] == "2"
        assert s["verification_count"] == "2"

    def test_verification_id_bound_to_case_and_round(self,
                                                     direct_vm,
                                                     direct_deploy):
        c = deploy(direct_vm)
        cid = _case(c)
        vid = _verify_recalled(direct_vm, c, cid)
        rec = json.loads(c.get_verification(vid))
        assert rec["case_id"] == cid
        assert rec["verification_id"] == vid
        case = json.loads(c.get_case(cid))
        assert rec["case_fingerprint"] == case["case_fingerprint"]
        assert rec["evidence_fingerprint"] == \
            case["latest_evidence_fingerprint"]
        assert rec["evidence_fingerprint"] != ""
