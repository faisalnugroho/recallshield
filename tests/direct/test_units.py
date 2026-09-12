"""Unit tests — deterministic layers of RecallShield.

Pure-function tests (loaded module, no deploy) + validation-path tests
(deployed contract) for:
  - helpers (_norm_ws, _norm_id, _canon_json, _strip_html, fingerprint)
  - URL validation (https-only, credentials, host forms, length)
  - create_case input validation (all fields, jurisdiction sub-national)
  - idempotent create (fingerprint dedup)
  - limits and counters
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import (  # noqa: E402
    deploy, llm_answer, std_case_kwargs, load_contract_module,
    MFR, MODEL, IDENT,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestNormHelpers:
    def test_norm_ws_collapses_and_strips(self):
        m = load_contract_module()
        assert m._norm_ws("  a \n\t b  c ") == "a b c"

    def test_norm_id_uppercase_alnum_only(self):
        m = load_contract_module()
        assert m._norm_id("af-3000_x!") == "AF3000X"
        assert m._norm_id("  ") == ""

    def test_canon_json_sorted_and_compact(self):
        m = load_contract_module()
        assert m._canon_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_strip_html_removes_tags_scripts_entities(self):
        m = load_contract_module()
        out = m._strip_html(
            "<p>Hello <b>world</b>!</p><script>evil()</script>"
            "<style>.x{}</style>&amp; end")
        # tags/entities are replaced by single spaces -> words separated
        assert "Hello" in out and "world" in out and "end" in out
        assert "evil" not in out
        assert ".x" not in out
        assert "&amp;" not in out
        assert "!" in out  # punctuation preserved, tags dropped
        # deterministic double-check: identical input -> identical output
        assert out == m._strip_html(
            "<p>Hello <b>world</b>!</p><script>evil()</script>"
            "<style>.x{}</style>&amp; end")

    def test_keccak_hex_known_vector(self):
        m = load_contract_module()
        # keccak-256("") canonical vector
        assert m._keccak_hex("") == \
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


class TestFingerprint:
    def test_fingerprint_order_independent_of_kwarg_order(self):
        m = load_contract_module()
        a = m._case_fingerprint(MFR, "name", "model", "ident",
                                "US", "cat", ["https://a.io/x"])
        b = m._case_fingerprint(MFR, "name", "model", "ident",
                                "US", "cat", ["https://a.io/x"])
        assert a == b and len(a) == 64

    def test_fingerprint_differs_on_any_identity_change(self):
        m = load_contract_module()
        base = ["https://a.io/x", "https://b.io/y"]
        f0 = m._case_fingerprint(MFR, "name", "model", "ident",
                                 "US", "cat", base)
        checks = [
            ("Other", "name", "model", "ident", "US", "cat", base),
            (MFR, "name2", "model", "ident", "US", "cat", base),
            (MFR, "name", "model2", "ident", "US", "cat", base),
            (MFR, "name", "model", "ident2", "US", "cat", base),
            (MFR, "name", "model", "ident", "DE", "cat", base),
            (MFR, "name", "model", "ident", "US", "cat2", base),
            (MFR, "name", "model", "ident", "US", "cat",
             ["https://b.io/y", "https://a.io/x"]),  # order too
        ]
        for args in checks:
            assert f0 != m._case_fingerprint(*args), str(args)


# ---------------------------------------------------------------------------
# URL validation (pure)
# ---------------------------------------------------------------------------

class TestValidateUrl:
    def test_valid_https(self):
        m = load_contract_module()
        assert m._validate_url("https://recalls.example.gov/x") is True
        assert m._validate_url("https://a.b.io/") is True
        assert m._validate_url("https://a.b.io:8443/x") is True

    def test_rejects_non_https_and_garbage(self):
        m = load_contract_module()
        bad = [
            "http://a.b.io/x",                    # not https
            "https://",                           # too short / no host
            "ftp://a.b.io/x",
            "https://a.b.io/x y",                 # whitespace
            "https://user:pass@a.b.io/",           # credentials
            "https://a b.io/",                    # space in host
            "https://a$bb.io/",                   # bad char in host
            "https://" + "x" * 250 + ".io/",      # too long overall
            "https://.a.io/",                     # leading dot host
            "https://a..io/",                     # double dot
            "https://-a.io/",                     # leading dash
            "https://a.b.io:port/",               # non-numeric port
        ]
        for u in bad:
            assert m._validate_url(u) is False, u

    def test_accepts_valid_and_rejects_type_fuzz(self):
        m = load_contract_module()
        assert m._validate_url(123) is False     # non-str
        assert m._validate_url(None) is False
        assert m._validate_url(["https://a.io"]) is False


# ---------------------------------------------------------------------------
# create_case input validation (deployed)
# ---------------------------------------------------------------------------

class TestCreateCaseValidation:
    def _c(self, direct_vm, direct_deploy):
        return deploy(direct_vm)

    def test_ok_minimal(self, direct_vm, direct_deploy):
        c = self._c(direct_vm, direct_deploy)
        cid = c.create_case(
            "ACME", "Widget", "W-1", "W1", "US", "tools",
            "https://a.example.gov/x", "regulator db")
        assert cid.startswith("rs")
        raw = c.get_case(cid)
        assert json.loads(raw)["manufacturer"] == "ACME"

    def test_rejects_empty_and_oversized_fields(self, direct_vm,
                                                direct_deploy):
        c = self._c(direct_vm, direct_deploy)
        bad_kw = [
            dict(manufacturer="", product_name="W", model_number="W1",
                 product_identifier="W1", jurisdiction="US",
                 category="tools"),
            dict(manufacturer="A" * 65, product_name="W",
                 model_number="W1", product_identifier="W1",
                 jurisdiction="US", category="tools"),
            dict(manufacturer="ACME", product_name="", model_number="W1",
                 product_identifier="W1", jurisdiction="US",
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="",
                 product_identifier="W1", jurisdiction="US",
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="W1",
                 product_identifier="", jurisdiction="US",
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="W1",
                 product_identifier="W1", jurisdiction="X",
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="W1",
                 product_identifier="W1", jurisdiction="US-",
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="W1",
                 product_identifier="W1", jurisdiction="U" * 9,
                 category="tools"),
            dict(manufacturer="ACME", product_name="W", model_number="W1",
                 product_identifier="W1", jurisdiction="US",
                 category="X" * 33),
        ]
        for kw in bad_kw:
            with direct_vm.expect_revert("invalid"):
                c.create_case(source_urls_csv="https://a.example.gov/x",
                              authority_labels_csv="regulator db", **kw)

    def test_jurisdiction_subnational_ok(self, direct_vm, direct_deploy):
        c = self._c(direct_vm, direct_deploy)
        for jur in ("US", "DE", "US-CA", "DE-BY", "GB-ENG", "CN-91"):
            cid = c.create_case(
                "ACME", "Widget", "W-1", "W1", jur, "tools",
                "https://a.example.gov/x", "regulator db")
            assert json.loads(c.get_case(cid))["jurisdiction"] == jur

    def test_rejects_bad_url_and_label_shapes(self, direct_vm,
                                              direct_deploy):
        c = self._c(direct_vm, direct_deploy)
        base = dict(manufacturer="ACME", product_name="W",
                    model_number="W1", product_identifier="W1",
                    jurisdiction="US", category="tools")
        with direct_vm.expect_revert("invalid_source_url"):
            c.create_case(source_urls_csv="http://a.example.gov/x",
                          authority_labels_csv="db", **base)
        with direct_vm.expect_revert("invalid_authority_label"):
            c.create_case(source_urls_csv="https://a.example.gov/x",
                          authority_labels_csv="", **base)
        with direct_vm.expect_revert("authority_label_count_mismatch"):
            # 2 urls, 1 label
            c.create_case(
                source_urls_csv="https://a.example.gov/x,https://b.io/y",
                authority_labels_csv="one", **base)
        with direct_vm.expect_revert("invalid_source_url_count"):
            # 4 urls > MAX_SOURCES
            c.create_case(
                source_urls_csv=",".join(["https://a%d.io/x" % i
                                         for i in range(4)]),
                authority_labels_csv="a,b,c,d", **base)
        with direct_vm.expect_revert("duplicate_source_url"):
            # duplicate urls
            c.create_case(
                source_urls_csv="https://a.example.gov/x,https://a.example.gov/x",
                authority_labels_csv="a,b", **base)


class TestCreateCaseIdempotence:
    def test_same_identity_returns_same_case_id(self, direct_vm,
                                                direct_deploy):
        c = deploy(direct_vm)
        kw = std_case_kwargs()
        cid1 = c.create_case(**kw)
        cid2 = c.create_case(**kw)
        assert cid1 == cid2
        stats = json.loads(c.get_stats())
        assert stats["case_count"] == "1"

    def test_different_source_set_new_case(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        kw = std_case_kwargs()
        cid1 = c.create_case(**kw)
        kw2 = dict(kw)
        kw2["source_urls_csv"] = kw["source_urls_csv"].split(",")[0]
        kw2["authority_labels_csv"] = "regulator database"
        cid2 = c.create_case(**kw2)
        assert cid1 != cid2
        assert json.loads(c.get_stats())["case_count"] == "2"


class TestViews:
    def test_get_case_absent_returns_empty(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        assert c.get_case("rs999999") == ""
        assert c.get_verification("rs000001-v001") == ""
        assert c.get_case_by_fingerprint("0x" + "ab" * 32) == ""
        assert json.loads(c.get_verification_history("rs999999")) == []
        s = json.loads(c.get_stats())
        assert s["case_count"] == "0"
        assert s["verification_count"] == "0"
        assert s["schema_version"] == "1.0"

    def test_verify_unknown_case_reverts(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        with direct_vm.expect_revert("case_not_found"):
            c.verify_case("rs999999")

    def test_reverify_never_verified_reverts(self, direct_vm,
                                             direct_deploy):
        c = deploy(direct_vm)
        kw = std_case_kwargs()
        cid = c.create_case(**kw)
        with direct_vm.expect_revert("case_never_verified"):
            c.reverify_case(cid)
