"""Content Credentials signed here, then read back through the real c2pa library.

Every fixture is made in the test: a throwaway ES256 certificate chain whose signer
carries only the C2PA claim-signing EKU (c2pa-kp-claimSigning, 1.3.6.1.4.1.62558.2.1,
C2PA 2.2 §14.4.1), small images drawn by Pillow and a short clip written by OpenCV,
signed with c2pa-python's Builder. Nothing here is real evidence, and the chain is
on no trust list GLEAPP carries.

These tests need the optional extra (``pip install -e ".[provenance]"``) and skip
without it; CI's Linux and Windows jobs install it.
"""

import hashlib
import io
import os
import sys

import pytest
from PIL import Image

from gleapp import provenance as pv

pytest.importorskip("c2pa")
# pylint: disable=wrong-import-position,wrong-import-order
from c2pasign import DST, created, make_chain, sign  # noqa: E402  pylint: disable=import-error


@pytest.fixture(scope="module", name="chain")
def _chain_fixture():
    """(signer, CA certificate PEM)."""
    return make_chain()


def _picture(fmt: str = "JPEG", **kw) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (48, 32), (30, 110, 170)).save(buf, fmt, **kw)
    return buf.getvalue()


def _write(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _read(path, trust=None):
    return pv.read_provenance(path, trust=trust or pv.bundled_trust_lists())


# -- the cases ------------------------------------------------------------------------

def test_a_generated_picture_by_an_unlisted_signer_is_valid_untrusted(tmp_path, chain):
    """The signer carries only the C2PA claim-signing EKU, as a certificate issued
    under the C2PA Trust List does. c2pa-rs 0.91.0 accepts that EKU only when it is
    named in trust.trust_config; without it this file read as invalid."""
    p = _write(tmp_path, "generated.jpg",
               sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia")))
    rec = _read(p)
    assert rec["state"] == "valid_untrusted", rec["codes"]["failure"]
    assert [c["code"] for c in rec["codes"]["failure"]] == ["signingCredential.untrusted"]
    assert rec["active_dst"] == DST + "trainedAlgorithmicMedia"
    assert rec["dst_class"] == "generative_ai"
    assert rec["dst_signed_valid"] is True
    assert rec["hard_binding_mismatch"] is False
    assert rec["signer"]["common_name"] == "Synthetic Signer"
    assert rec["signer"]["issuer"] == "Synthetic Test Org"
    assert rec["claim_generator"].startswith("Synthetic Generator 1.0")
    assert rec["store_in_bytes"] == "JPEG APP11"
    assert rec["library_version"].startswith("c2pa-python 0.38")
    assert rec["trusted_by"] is None and rec["trust_list_sha256"] is None


def test_a_changed_byte_breaks_the_hard_binding(tmp_path, chain):
    signed = bytearray(sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia")))
    signed[-10] ^= 0xFF                       # inside the entropy-coded scan, before EOI
    rec = _read(_write(tmp_path, "changed.jpg", bytes(signed)))
    assert rec["state"] == "invalid"
    assert rec["hard_binding_mismatch"] is True
    assert "assertion.dataHash.mismatch" in [c["code"] for c in rec["codes"]["failure"]]
    # what it declared is still recorded, marked as not backed by a valid signature
    assert rec["dst_class"] == "generative_ai"
    assert rec["dst_signed_valid"] is False


def test_a_capture(tmp_path, chain):
    rec = _read(_write(tmp_path, "capture.jpg",
                       sign(chain, _picture(), "image/jpeg", created("digitalCapture"))))
    assert rec["state"] == "valid_untrusted"
    assert rec["dst_class"] == "capture"


def test_a_composite_synthetic(tmp_path, chain):
    rec = _read(_write(tmp_path, "composite.jpg",
                       sign(chain, _picture(), "image/jpeg", created("compositeSynthetic"))))
    assert rec["dst_class"] == "ai_composite"
    assert rec["active_dst"] == DST + "compositeSynthetic"


def test_an_ai_ingredient_inside_an_edit_that_declares_nothing(tmp_path, chain):
    generated = sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia"))
    edit = [{"action": "c2pa.opened", "parameters": {"ingredientIds": ["ingredient-1"]}},
            {"action": "c2pa.edited"}]
    p = _write(tmp_path, "edited.jpg", sign(chain, _picture(), "image/jpeg", edit,
                                             ingredient=generated, generator="Synthetic Editor"))
    rec = _read(p)
    assert rec["state"] == "valid_untrusted"
    assert rec["active_dst"] is None and rec["dst_class"] == "none"
    assert rec["claim_generator"].startswith("Synthetic Editor")
    assert len(rec["ingredients"]) == 1
    ing = rec["ingredients"][0]
    assert ing["title"] == "ingredient.jpg"
    assert ing["dst_class"] == "generative_ai"
    assert ing["state"] == "valid_untrusted"
    assert ing["signer"]["common_name"] == "Synthetic Signer"


def test_a_picture_with_no_credentials_is_absent(tmp_path):
    rec = _read(_write(tmp_path, "plain.jpg", _picture()))
    assert rec["state"] == "absent"
    assert rec["xmp_dst"] is None


def test_without_the_library_a_signed_file_is_not_checked(tmp_path, chain, monkeypatch):
    p = _write(tmp_path, "generated.jpg",
               sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia")))
    monkeypatch.setitem(sys.modules, "c2pa", None)
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"] == pv.NOT_CHECKED_LIBRARY
    assert rec["store_in_bytes"] == "JPEG APP11"


def test_an_xmp_source_type_without_credentials_is_an_unsigned_declaration(tmp_path):
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
           b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description '
           b'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
           b'Iptc4xmpExt:DigitalSourceType="' + DST.encode() + b'trainedAlgorithmicMedia"/>'
           b'</rdf:RDF></x:xmpmeta>')
    rec = _read(_write(tmp_path, "declared.jpg", _picture(xmp=xmp)))
    assert rec["state"] == "absent"
    assert rec["xmp_dst"] == {"uri": DST + "trainedAlgorithmicMedia", "class": "generative_ai",
                              "label": "unsigned declaration",
                              "field": "XMP Iptc4xmpExt:DigitalSourceType"}
    # kept apart from the C2PA fields, never folded into them
    assert rec["active_dst"] is None and rec["dst_class"] == "none"


def test_a_signer_on_an_examiner_list_is_trusted_and_the_list_named(tmp_path, chain):
    _signer, ca_pem = chain
    anchors = _write(tmp_path, "synthetic-ca.pem", ca_pem)
    p = _write(tmp_path, "generated.jpg",
               sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia")))
    rec = pv.read_provenance(p, trust=pv.trust_lists(signer_anchors=anchors))
    assert rec["state"] == "trusted", rec["codes"]["failure"]
    assert rec["codes"]["failure"] == []
    assert rec["trusted_by"] == "examiner signer anchors: synthetic-ca.pem"
    assert rec["trust_list_sha256"] == hashlib.sha256(ca_pem).hexdigest()
    assert [a["label"] for a in rec["trust_lists"]][:2] == [
        "C2PA Trust List (bundled, conformance-public 43a0a6f)",
        "C2PA TSA Trust List (bundled, conformance-public 43a0a6f)"]


def test_a_signer_trusted_only_through_a_tsa_anchor_is_not_trusted(tmp_path, chain):
    """c2pa-rs 0.91.0 reports Trusted here; the TSA list does not vouch for signers."""
    _signer, ca_pem = chain
    p = _write(tmp_path, "generated.jpg",
               sign(chain, _picture(), "image/jpeg", created("trainedAlgorithmicMedia")))
    trust = pv.TrustLists((pv.Anchor("tsa", ca_pem, "synthetic CA loaded as a TSA"),))
    rec = pv.read_provenance(p, trust=trust)
    assert rec["state"] == "valid_untrusted"
    assert "TSA" in rec["state_reason"]


def test_png_and_webp_carry_their_store_where_the_scan_looks(tmp_path, chain):
    for fmt, mime, where in (("PNG", "image/png", "PNG caBX"),
                             ("WEBP", "image/webp", "WebP C2PA")):
        p = _write(tmp_path, "g." + fmt.lower(),
                   sign(chain, _picture(fmt), mime, created("trainedAlgorithmicMedia")))
        rec = _read(p)
        assert rec["store_in_bytes"] == where, fmt
        assert rec["state"] == "valid_untrusted", (fmt, rec["codes"]["failure"])
        assert rec["dst_class"] == "generative_ai", fmt


def test_a_signed_clip(tmp_path, chain):
    cv2 = pytest.importorskip("cv2")
    import numpy as np  # pylint: disable=import-outside-toplevel
    raw = tmp_path / "raw.mp4"
    writer = cv2.VideoWriter(str(raw), cv2.VideoWriter_fourcc(*"mp4v"), 10, (64, 48))
    assert writer.isOpened(), "OpenCV could not write an MP4 here"
    for i in range(10):
        writer.write(np.full((48, 64, 3), i * 20, np.uint8))
    writer.release()
    p = _write(tmp_path, "clip.mp4", sign(chain, raw.read_bytes(), "video/mp4",
                                          created("trainedAlgorithmicMedia")))
    rec = _read(p)
    assert rec["store_in_bytes"] == "ISOBMFF C2PA uuid box"
    assert rec["state"] == "valid_untrusted", rec["codes"]["failure"]
    assert rec["dst_class"] == "generative_ai"


def test_a_container_the_scan_does_not_walk_is_left_to_the_reader(tmp_path):
    """GLEAPP's scan walks JPEG, PNG, WebP, TIFF and ISOBMFF. Anything else goes to
    the reader, which names the format from the bytes: a GIF it reads and finds
    nothing in, a BMP it does not support, which says nothing about a manifest."""
    gif = _read(_write(tmp_path, "a.gif", _picture("GIF")))
    assert gif["state"] == "absent"
    assert gif["state_reason"] == pv.ABSENT_BY_READER
    bmp = _read(_write(tmp_path, "a.bmp", _picture("BMP")))
    assert bmp["state"] == "not_checked"
    assert bmp["state_reason"].startswith(
        "C2PA not checked: the c2pa reader does not support this format")


def test_reading_never_writes_to_the_file(tmp_path, chain):
    data = sign(chain, _picture(), "image/jpeg", created("digitalCapture"))
    p = _write(tmp_path, "capture.jpg", data)
    before = os.stat(p)
    _read(p)
    assert p.read_bytes() == data
    assert os.stat(p).st_mtime_ns == before.st_mtime_ns
    assert sorted(x.name for x in tmp_path.iterdir()) == ["capture.jpg"]
