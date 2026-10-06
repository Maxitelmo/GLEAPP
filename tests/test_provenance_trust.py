"""The C2PA trust lists GLEAPP carries, and the anchors an examiner adds to them.

``trusted`` means the signer's certificate chains to an anchor on a list GLEAPP holds.
C2PA 2.2 §14.4.1 and §14.4.2: a validator's anchors include the C2PA Trust List and
the C2PA TSA Trust List, and a user should be able to add anchors of their own. So
GLEAPP carries both lists as published in c2pa-org/conformance-public, unmodified,
with hashes and certificate counts pinned here so that refreshing them is a
decision with a diff; an examiner's anchors are added to them, never put in their
place; and only a newer copy of C2PA's own lists can stand in for the copies
GLEAPP carries. Every record names the lists it was read with and the one, if any,
that a trusted signer chained to.
"""

import hashlib
import io
import json
import re
from pathlib import Path

import pytest
from PIL import Image

from c2pafake import install_fake_c2pa  # pylint: disable=import-error
from gleapp import appconfig
from gleapp import provenance as pv

ROOT = Path(__file__).resolve().parents[1]
TRUST = ROOT / "gleapp" / "trust"

# conformance-public at 43a0a6f09091a062083a4ba33e3acc19dd721282, fetched 2026-10-06
PINNED = {
    "C2PA-TRUST-LIST.pem": (
        "75cacc98b79ecac33713c7ecfb58d4a0ef383f3c1f886e7409f9e37e8664aea5", 30),
    "C2PA-TSA-TRUST-LIST.pem": (
        "c688d3555f4a2f1f8d663472bbd37888ff234abdd234c25934c0f9292e4eb5c9", 22),
}
SIGNERS = PINNED["C2PA-TRUST-LIST.pem"][0]
TSAS = PINNED["C2PA-TSA-TRUST-LIST.pem"][0]


@pytest.fixture(autouse=True)
def _isolate_appconfig(tmp_path_factory, monkeypatch):
    """The trust lists set here must not reach another test's reads."""
    monkeypatch.setenv("GLEAPP_CONFIG_DIR", str(tmp_path_factory.mktemp("gleapp-cfg")))


def _jpeg_with_store() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), "white").save(buf, "JPEG")
    data = buf.getvalue()
    app11 = b"JP\x00\x01\x00\x00\x00\x01" + b"\x00\x00\x00\x10jumb" + b"\x00\x00\x00\x08c2pa"
    return data[:2] + b"\xff\xeb" + (len(app11) + 2).to_bytes(2, "big") + app11 + data[2:]


def _pem(tmp_path, name, body=b"MIIB"):
    p = tmp_path / name
    p.write_bytes(b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----\n")
    return p


def _shas(trust):
    return [(a.kind, a.sha256) for a in trust.anchors]


# -- what GLEAPP carries ---------------------------------------------------------------

def test_the_bundled_lists_are_the_pinned_files():
    for name, (sha256, certificates) in PINNED.items():
        data = (TRUST / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256, name
        assert data.count(b"-----BEGIN CERTIFICATE-----") == certificates, name
        assert data.count(b"-----END CERTIFICATE-----") == certificates, name
        assert b"\r" not in data, name


def test_the_manifest_and_the_readme_record_where_they_came_from():
    manifest = json.loads((TRUST / "trust_lists.json").read_text(encoding="utf-8"))
    assert manifest["source"] == "https://github.com/c2pa-org/conformance-public"
    assert manifest["licence"] == "CC-BY-4.0"
    assert manifest["licence_file"] == "gleapp/trust/LICENSE-c2pa-trust-lists"
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["commit"])
    readme = (TRUST / "README.md").read_text(encoding="utf-8")
    assert manifest["commit"] in readme
    files = {f["name"]: f for f in manifest["files"]}
    assert set(files) == set(PINNED)
    for name, (sha256, certificates) in PINNED.items():
        assert files[name]["sha256"] == sha256
        assert files[name]["certificates"] == certificates
        assert re.fullmatch(r"[0-9a-f]{40}", files[name]["last_changed_in"])
        assert sha256 in readme and files[name]["last_changed_in"] in readme
    assert {f["kind"] for f in manifest["files"]} == {"manifest", "tsa"}


def test_the_wheel_and_the_frozen_build_carry_them():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"trust/*",' in pyproject
    assert '"gleapp/trust/LICENSE-*",' in pyproject
    spec = (ROOT / "packaging" / "gleapp.spec").read_text(encoding="utf-8")
    assert '(str(PKG / "trust"), "gleapp/trust"),' in spec


def test_the_bundled_lists_load_and_say_where_they_came_from():
    trust = pv.bundled_trust_lists()
    assert _shas(trust) == [("manifest", SIGNERS), ("tsa", TSAS)]
    assert [a.label for a in trust.anchors] == [
        "C2PA Trust List (bundled, conformance-public 43a0a6f)",
        "C2PA TSA Trust List (bundled, conformance-public 43a0a6f)"]


# -- what the examiner adds ------------------------------------------------------------

def test_examiner_anchors_are_added_to_the_c2pa_lists_never_in_their_place(tmp_path):
    signer = _pem(tmp_path, "lab-ca.pem")
    tsa = _pem(tmp_path, "lab-tsa.pem", b"MIIC")
    trust = pv.trust_lists(signer_anchors=signer, tsa_anchors=tsa)
    assert _shas(trust) == [("manifest", SIGNERS), ("tsa", TSAS),
                            ("manifest", hashlib.sha256(signer.read_bytes()).hexdigest()),
                            ("tsa", hashlib.sha256(tsa.read_bytes()).hexdigest())]
    assert [a.label for a in trust.anchors[2:]] == [
        "examiner signer anchors: lab-ca.pem", "examiner TSA anchors: lab-tsa.pem"]
    assert all(str(tmp_path) not in a.label for a in trust.anchors)


def test_a_newer_copy_of_a_c2pa_list_stands_in_for_the_bundled_copy(tmp_path):
    newer = _pem(tmp_path, "C2PA-TRUST-LIST-2026-12.pem")
    trust = pv.trust_lists(c2pa_list=newer)
    assert _shas(trust) == [("manifest", hashlib.sha256(newer.read_bytes()).hexdigest()),
                            ("tsa", TSAS)]
    assert trust.anchors[0].label == "C2PA Trust List (examiner copy: C2PA-TRUST-LIST-2026-12.pem)"


def test_a_file_that_holds_no_certificate_is_refused(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("not a certificate", encoding="utf-8")
    with pytest.raises(pv.TrustListError) as err:
        pv.trust_lists(signer_anchors=p)
    assert str(tmp_path) not in str(err.value)
    with pytest.raises(pv.TrustListError) as err:
        pv.trust_lists(c2pa_tsa_list=tmp_path / "missing.pem")
    assert str(tmp_path) not in str(err.value)


def test_the_examiner_lists_are_kept_in_the_app_config(tmp_path):
    empty = {"c2pa_list": None, "c2pa_tsa_list": None, "signer_anchors": None,
             "tsa_anchors": None}
    assert appconfig.get_c2pa_trust_lists() == empty
    p = _pem(tmp_path, "lab-ca.pem")
    appconfig.set_c2pa_trust_lists(signer_anchors=str(p))
    assert appconfig.get_c2pa_trust_lists() == dict(empty, signer_anchors=str(p))
    assert pv.configured_trust_lists().anchors[-1].pem == p.read_bytes()
    appconfig.set_c2pa_trust_lists()
    assert appconfig.get_c2pa_trust_lists() == empty
    assert _shas(pv.configured_trust_lists()) == [("manifest", SIGNERS), ("tsa", TSAS)]


def test_the_app_config_refuses_a_key_it_does_not_know():
    with pytest.raises(TypeError):
        appconfig.set_c2pa_trust_lists(replace_everything="x.pem")  # pylint: disable=unexpected-keyword-arg


# -- what a record says ---------------------------------------------------------------

def test_a_file_is_read_with_the_configured_lists_and_says_which(tmp_path, monkeypatch):
    lib = install_fake_c2pa(monkeypatch, raises=lambda f: f.C2paError.ManifestNotFound("none"))
    p = tmp_path / "a.jpg"
    p.write_bytes(_jpeg_with_store())
    pv.read_provenance(p)
    anchors = lib.settings[0]["trust"]["anchors"]
    assert [a["trust_kind"] for a in anchors] == ["manifest", "tsa"]
    assert hashlib.sha256(anchors[0]["trust_anchors"].encode()).hexdigest() == SIGNERS
    assert hashlib.sha256(anchors[1]["trust_anchors"].encode()).hexdigest() == TSAS


def test_a_trusted_record_names_the_list_the_signer_chained_to(tmp_path, monkeypatch):
    trust = pv.bundled_trust_lists()
    label = "urn:c2pa:00000000-0000-4000-8000-00000000000a"
    store = {"active_manifest": label, "validation_state": "Trusted",
             "manifests": {label: {"label": label, "assertions": [],
                                   "signature_info": {"issuer": "Synthetic Test Org",
                                                      "common_name": "Synthetic Signer"}}},
             "validation_results": {"activeManifest": {
                 "success": [{"code": "signingCredential.trusted"}],
                 "informational": [], "failure": []},
                 "trustListUri": trust.anchors[0].uri}}
    install_fake_c2pa(monkeypatch, store=store)
    p = tmp_path / "a.jpg"
    p.write_bytes(_jpeg_with_store())
    rec = pv.read_provenance(p, trust=trust)
    assert rec["state"] == "trusted"
    assert rec["trusted_by"] == "C2PA Trust List (bundled, conformance-public 43a0a6f)"
    assert rec["trust_list_sha256"] == SIGNERS
    assert rec["trust_lists"] == [
        {"kind": "manifest", "label": "C2PA Trust List (bundled, conformance-public 43a0a6f)",
         "sha256": SIGNERS},
        {"kind": "tsa", "label": "C2PA TSA Trust List (bundled, conformance-public 43a0a6f)",
         "sha256": TSAS}]


def test_a_configured_list_that_cannot_be_read_is_reported_never_swapped(tmp_path, monkeypatch):
    """Falling back to the bundled list would record a result the examiner did not
    ask for; the file is not read at all instead, and the record says why."""
    lib = install_fake_c2pa(monkeypatch, raises=lambda f: AssertionError("must not be read"))
    appconfig.set_c2pa_trust_lists(signer_anchors=str(tmp_path / "gone.pem"))
    p = tmp_path / "a.jpg"
    p.write_bytes(_jpeg_with_store())
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"].startswith("C2PA not checked: trust list could not be read")
    assert "gone.pem" in rec["state_reason"]
    assert str(tmp_path) not in rec["state_reason"]
    assert lib.calls == []


def test_a_file_with_no_store_is_absent_whatever_the_trust_lists(tmp_path, monkeypatch):
    install_fake_c2pa(monkeypatch, raises=lambda f: AssertionError("must not be read"))
    appconfig.set_c2pa_trust_lists(signer_anchors=str(tmp_path / "gone.pem"))
    p = tmp_path / "plain.jpg"
    Image.new("RGB", (8, 8)).save(p, "JPEG")
    assert pv.read_provenance(p)["state"] == "absent"


def test_the_real_reader_accepts_the_bundled_lists():
    c2pa = pytest.importorskip("c2pa")
    settings = c2pa.Settings.from_dict(pv.reader_settings(pv.bundled_trust_lists()))
    c2pa.Context(settings=settings)
