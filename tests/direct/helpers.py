"""Shared direct-mode test helpers for RecallShield.

  - mock_body(): dict-format web mock (string bodies fetch EMPTY —
    verified gltest pitfall); URL regex-escaped
  - llm_answer(): builds a well-formed extractor payload for mock_llm
  - page(): builds recall-page HTML fed to the strip-HTML pipeline
  - deploy() wrapper + contract module loader for pure-function tests
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CONTRACT = str(ROOT / "contracts" / "recall_shield.py")


def mock_body(vm, url, body, status=200):
    # DICT format is mandatory — string bodies fetch EMPTY.
    # URL is escaped: '?' and '.' are regex metachars (verified pitfall).
    vm.mock_web(re.escape(url), {"status": status, "body": body})


def deploy(vm, contract_path=CONTRACT):
    from gltest.direct.loader import deploy_contract
    return deploy_contract(contract_path, vm)


# ---------------------------------------------------------------------------
# Well-formed extractor payloads
# ---------------------------------------------------------------------------

def llm_answer(
    *,
    is_recall_content=True,
    recall_present=True,
    authority_class="REGULATOR",
    authority_observed="Consumer Product Safety Commission",
    manufacturer_stated="ACME",
    affected_models=None,
    manufacturer_match=True,
    model_match=False,
    matched_model="",
    family_covers_model=False,
    recall_reference="",
    recall_date="",
    recall_language="",
    schema_version=1,
    source_reachable=True,
    extra=None,
):
    """Build a well-formed LLM extraction JSON for mock_llm.

    affected_models: list of affected-model strings (max 12).
    """
    d = {
        "schema_version": schema_version,
        "source_reachable": source_reachable,
        "is_recall_content": is_recall_content,
        "recall_present": recall_present,
        "authority_class": authority_class,
        "authority_observed": authority_observed,
        "manufacturer_stated": manufacturer_stated,
        "affected_models": affected_models if affected_models is not None else [],
        "manufacturer_match": manufacturer_match,
        "model_match": model_match,
        "matched_model": matched_model,
        "family_covers_model": family_covers_model,
        "recall_reference": recall_reference,
        "recall_date": recall_date,
        "recall_language": recall_language,
    }
    if extra:
        d.update(extra)
    return json.dumps(d)


def page(title="Recall Database", body="...", scripts=False):
    """Build recall-page HTML for the fetch -> strip pipeline."""
    s = "<script>alert(1)</script>" if scripts else ""
    return ("<html><head><title>" + title + "</title></head>" + s +
            "<body>" + body + "</body></html>")


# ---------------------------------------------------------------------------
# Standard product identities used across test files
# ---------------------------------------------------------------------------

MFR = "ACME Appliances"
PNAME = "Air Fryer 3000"
MODEL = "AF-3000"
IDENT = "AF3000X"
JUR = "US"
CAT = "appliances"

URLS = [
    "https://recalls.example.gov/search?product=air+fryer",
    "https://acme.example.com/recalls",
    "https://news.example.org/safety",
]
AUTH_LABELS = "regulator database,manufacturer site,news outlet"


def std_case_kwargs():
    """create_case kwargs for the standard ACME fixture."""
    return dict(
        manufacturer=MFR,
        product_name=PNAME,
        model_number=MODEL,
        product_identifier=IDENT,
        jurisdiction=JUR,
        category=CAT,
        source_urls_csv=URLS[0] + "," + URLS[1],
        authority_labels_csv="regulator database,manufacturer site",
    )


_M = None


def load_contract_module():
    """Load the contract module ONCE for pure-function unit tests.

    Reuses the loader under the same activate() protocol the pytest
    fixtures use; the captured module reference keeps pure functions
    alive even after cleanup evicts _contract_* from sys.modules.
    """
    global _M
    if _M is not None:
        return _M
    for name, mod in list(sys.modules.items()):
        if name.startswith("_contract_recall_shield") and \
                hasattr(mod, "STATUSES"):
            _M = mod
            return _M
    from gltest.direct.vm import VMContext
    from gltest.direct.loader import create_address, load_contract_class
    vm = VMContext()
    vm.sender = create_address("unit-bootstrap")
    with vm.activate():
        load_contract_class(Path(CONTRACT), vm)
        for name, mod in list(sys.modules.items()):
            if name.startswith("_contract_recall_shield") and \
                    hasattr(mod, "STATUSES"):
                _M = mod
                break
    assert _M is not None, "contract module did not load"
    return _M
