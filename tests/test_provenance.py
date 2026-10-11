"""gleapp.provenance: Content Credentials and IPTC digital source type as metadata.

The manifest stores here are written by hand in the shape c2pa-python 0.38.0
(c2pa-rs 0.91.0) returns from ``Reader.json()``, with synthetic labels, signers and
titles. The c2pa library itself is replaced by a stand-in module, so these tests run
without the optional extra; the tests that sign real fixtures are in
test_provenance_signed.py.
"""

import io
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest
from PIL import Image

from c2pafake import install_fake_c2pa  # pylint: disable=import-error
from gleapp import provenance as pv

DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"
ACTIVE = "urn:c2pa:00000000-0000-4000-8000-00000000000a"
CHILD = "urn:c2pa:00000000-0000-4000-8000-00000000000b"
GRANDCHILD = "urn:c2pa:00000000-0000-4000-8000-00000000000c"


def _code(code, explanation="synthetic"):
    return {"code": code, "url": "self#jumbf=/c2pa/x", "explanation": explanation}


def _manifest(label, dst=None, *, action="c2pa.created", ingredients=(), signer="Synthetic Signer"):
    actions = [{"action": action, "digitalSourceType": DST + dst}] if dst else \
        [{"action": "c2pa.opened"}, {"action": "c2pa.edited"}]
    m = {
        "claim_generator_info": [{"name": "Synthetic Tool", "version": "1.0",
                                  "org.contentauth.c2pa_rs": "0.91.0"}],
        "title": "synthetic.jpg",
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": actions}}],
        "signature_info": {"alg": "Es256", "issuer": "Synthetic Test Org",
                           "common_name": signer, "cert_serial_number": "2",
                           "time": "2026-01-02T03:04:05+00:00"},
        "label": label,
        "claim_version": 2,
    }
    if ingredients:
        m["ingredients"] = list(ingredients)
    return m


def _results(success=(), failure=(), deltas=None, trust_uri=None):
    active = {"success": [_code(c) for c in ("claimSignature.validated", *success)],
              "informational": [_code("signingCredential.ocsp.skipped")],
              "failure": [_code(c) for c in failure]}
    out = {"activeManifest": active, "specVersion": "2.4.0"}
    if deltas is not None:
        out["ingredientDeltas"] = deltas
    if trust_uri:
        out["trustListUri"] = trust_uri
    return out


def _store(manifest, state="Valid", results=None, others=()):
    manifests = {manifest["label"]: manifest}
    for m in others:
        manifests[m["label"]] = m
    store = {"active_manifest": manifest["label"], "manifests": manifests,
             "validation_results": results if results is not None else
             _results(failure=["signingCredential.untrusted"])}
    if state is not None:
        store["validation_state"] = state
    return store


def _ingredient(child_label, label="c2pa.ingredient.v3", failure=(), title="ingredient.jpg"):
    return {"title": title, "relationship": "parentOf", "label": label,
            "active_manifest": child_label,
            "validation_results": {"activeManifest": {
                "success": [_code("claimSignature.validated")], "informational": [],
                "failure": [_code(c) for c in failure]}}}


# -- the vocabulary -------------------------------------------------------------------

@pytest.mark.parametrize("term, cls", [
    ("trainedAlgorithmicMedia", "generative_ai"),
    ("compositeWithTrainedAlgorithmicMedia", "ai_edited"),
    ("compositeSynthetic", "ai_composite"),
    ("virtualRecording", "virtual_recording"),
    ("algorithmicMedia", "algorithmic"),
    ("digitalCapture", "capture"),
    ("computationalCapture", "capture"),
    ("negativeFilm", "capture"),
    ("positiveFilm", "capture"),
    ("print", "capture"),
    ("screenCapture", "screen"),
    ("humanEdits", "human_edit"),
    ("minorHumanEdits", "human_edit"),
    ("composite", "composite"),
    ("compositeCapture", "composite_capture"),
    ("algorithmicallyEnhanced", "algorithmically_altered"),
    ("dataDrivenMedia", "other"),
])
def test_each_iptc_term_falls_in_its_class(term, cls):
    assert pv.classify_dst(DST + term) == cls


# The terms whose IPTC definition includes generative AI (Digital Source Type
# vocabulary, https://cv.iptc.org/newscodes/digitalsourcetype/, release of 2024-10-23),
# and C2PA's trainedAlgorithmicData (C2PA 2.2 §18.14.4.5). Only these may fall in a
# class whose label names AI: virtualRecording, a live recording of a virtual event
# "based on Generative AI and/or captured elements" (IPTC), can hold no AI at all.
AI_BY_DEFINITION = {"trainedAlgorithmicMedia", "trainedAlgorithmicData",
                    "compositeWithTrainedAlgorithmicMedia", "compositeSynthetic"}


def test_only_a_term_defined_as_generative_ai_falls_in_a_class_named_ai():
    named = {term for cls, terms in pv._DST_GROUPS.items()  # pylint: disable=protected-access
             if "AI" in pv.DST_CLASS_LABELS[cls].split() for term in terms}
    assert named == AI_BY_DEFINITION


def test_a_virtual_event_recording_is_not_an_ai_class():
    cls = pv.classify_dst(DST + "virtualRecording")
    assert cls == "virtual_recording"
    assert pv.DST_CLASS_LABELS[cls] == "Virtual event recording"
    assert "AI" not in pv.DST_CLASS_LABELS[cls].split()


def test_human_edits_holds_only_the_edits_iptc_attributes_to_a_human():
    assert set(pv._DST_GROUPS["human_edit"]) == {  # pylint: disable=protected-access
        "humanEdits", "minorHumanEdits"}


@pytest.mark.parametrize("term, label", [
    # IPTC's labels: elements that may or may not be generative AI; elements that are
    # all captured from real life; an algorithm's change that leaves the main content
    ("composite", "Composite of elements"),
    ("compositeCapture", "Composite of captured elements"),
    ("algorithmicallyEnhanced", "Algorithmically-altered media"),
])
def test_a_term_that_is_not_a_human_edit_is_named_as_iptc_names_it(term, label):
    cls = pv.classify_dst(DST + term)
    assert pv.DST_CLASS_LABELS[cls] == label
    assert pv._DST_GROUPS[cls] == (term,)  # pylint: disable=protected-access


# The terms IPTC has retired (release of 2024-10-23). A file can still declare
# one: it is read, keeps its class, and says it is retired wherever the term is shown.
RETIRED = ("minorHumanEdits", "digitalArt", "softwareImage")


def _declaring(active, ingredient, xmp):
    child = _manifest(CHILD, ingredient)
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, active,
                                                   ingredients=[_ingredient(CHILD)]),
                                         others=[child]))
    rec["xmp_dst"] = {"uri": xmp, "class": pv.classify_dst(xmp), "label": pv.UNSIGNED}
    return dict(pv.describe(rec))


def test_a_term_iptc_has_retired_is_marked_wherever_it_is_shown():
    rows = _declaring("minorHumanEdits", "digitalArt", DST + "softwareImage")
    assert rows["Declared source type"] == "minorHumanEdits, retired by IPTC (Human edits)"
    assert "ingredient.jpg: digitalArt, retired by IPTC (Other); " in rows["Ingredients"]
    assert rows["XMP source type"] == ("softwareImage, retired by IPTC (Other), "
                                       "unsigned declaration")
    for term in RETIRED:                 # read as before: retiring a term moves nothing
        assert pv.classify_dst(DST + term) == ("human_edit" if term == "minorHumanEdits"
                                               else "other")


def test_a_current_term_or_another_namespace_is_not_marked_retired():
    rows = _declaring("humanEdits", "digitalCapture",
                      "https://example.invalid/digitalsourcetype/minorHumanEdits")
    assert rows["Declared source type"] == "humanEdits (Human edits)"
    assert "retired" not in rows["Ingredients"]
    assert rows["XMP source type"] == "minorHumanEdits (Other), unsigned declaration"


def test_the_c2pa_namespace_terms_are_classified():
    assert pv.classify_dst("http://c2pa.org/digitalsourcetype/trainedAlgorithmicData") \
        == "generative_ai"
    assert pv.classify_dst("http://c2pa.org/digitalsourcetype/empty") == "other"
    assert pv.classify_dst("c2pa.trainedAlgorithmicData") == "generative_ai"


def test_a_term_is_matched_on_its_whole_last_segment_only():
    """compositeWithTrainedAlgorithmicMedia contains trainedAlgorithmicMedia; a
    substring match would call every AI composite fully generated."""
    assert pv.classify_dst(DST + "compositeWithTrainedAlgorithmicMedia") == "ai_edited"
    assert pv.classify_dst(DST + "trainedAlgorithmicMediaX") == "other"
    assert pv.classify_dst("https://example.invalid/digitalsourcetype/trainedAlgorithmicMedia") \
        == "other"


def test_no_source_type_is_none():
    assert pv.classify_dst(None) == "none"
    assert pv.classify_dst("") == "none"


def test_every_class_is_one_of_the_declared_ones():
    terms = [t for ts in pv._DST_GROUPS.values() for t in ts]  # pylint: disable=protected-access
    assert {pv.classify_dst(DST + t) for t in terms} <= set(pv.DST_CLASSES)


# -- the manifest store ---------------------------------------------------------------

def test_a_generated_image_signed_by_an_unlisted_signer_is_valid_untrusted():
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "trainedAlgorithmicMedia")))
    assert rec["state"] == "valid_untrusted"
    assert rec["active_dst"] == DST + "trainedAlgorithmicMedia"
    assert rec["dst_class"] == "generative_ai"
    assert rec["dst_action"] == "c2pa.created"
    assert rec["dst_signed_valid"] is True
    assert rec["hard_binding_mismatch"] is False
    assert rec["signer"] == {"issuer": "Synthetic Test Org", "common_name": "Synthetic Signer",
                             "cert_serial_number": "2"}
    assert pv.signer_text(rec["signer"]) == "Synthetic Signer (Synthetic Test Org)"
    assert rec["claim_generator"] == "Synthetic Tool 1.0"
    assert rec["signed_time"] == "2026-01-02T03:04:05+00:00"
    assert rec["spec_version"] == "2.4.0"
    assert [c["code"] for c in rec["codes"]["failure"]] == ["signingCredential.untrusted"]
    assert [c["code"] for c in rec["codes"]["informational"]] == ["signingCredential.ocsp.skipped"]


def test_a_signer_on_the_trust_list_is_trusted():
    results = _results(success=["signingCredential.trusted"], trust_uri="gleapp:signer")
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "digitalCapture"), "Trusted", results))
    assert rec["state"] == "trusted"
    assert rec["dst_class"] == "capture"
    assert rec["trust_list_uri"] == "gleapp:signer"


def test_trusted_only_through_the_tsa_list_is_not_trusted():
    """c2pa-rs 0.91.0 trusts a signer that chains to an anchor loaded as a TSA; the TSA
    list vouches for time-stamping authorities, not for signers."""
    results = _results(success=["signingCredential.trusted"], trust_uri="gleapp:tsa")
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "digitalCapture"), "Trusted", results),
                                  tsa_uris=["gleapp:tsa"])
    assert rec["state"] == "valid_untrusted"
    assert "TSA" in rec["state_reason"]


def test_a_changed_byte_is_invalid_and_the_declaration_is_kept_but_marked():
    """C2PA 2.2 §15.3: what a manifest that is not valid declares is not attributable
    to its signer. It is recorded, and marked as not backed by a valid signature."""
    results = _results(failure=["signingCredential.untrusted", "assertion.dataHash.mismatch"])
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "trainedAlgorithmicMedia"),
                                         "Invalid", results))
    assert rec["state"] == "invalid"
    assert rec["hard_binding_mismatch"] is True
    assert rec["active_dst"] == DST + "trainedAlgorithmicMedia"
    assert rec["dst_class"] == "generative_ai"
    assert rec["dst_signed_valid"] is False


@pytest.mark.parametrize("code", sorted(pv.HARD_BINDING_MISMATCH))
def test_every_hard_binding_mismatch_is_flagged(code):
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "digitalCapture"), "Invalid",
                                         _results(failure=[code])))
    assert rec["hard_binding_mismatch"] is True
    assert rec["state"] == "invalid"


def test_an_invalid_store_with_a_well_formedness_failure_is_malformed():
    results = _results(failure=["claim.malformed"])
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "digitalCapture"), "Invalid", results))
    assert rec["state"] == "malformed"
    assert rec["dst_signed_valid"] is False


def test_a_store_without_its_active_manifest_is_malformed():
    store = _store(_manifest(ACTIVE, "digitalCapture"))
    store["active_manifest"] = "urn:c2pa:missing"
    rec = pv.parse_manifest_store(store)
    assert rec["state"] == "malformed"


def test_cawg_identity_results_do_not_decide_the_state():
    """CAWG identity assertions say who claims to be behind a manifest, separately
    from the claim signature; GLEAPP does not decode them (their did:web issuers are
    fetched), and their failures do not make the claim invalid."""
    results = _results(failure=["signingCredential.untrusted", "cawg.identity.well-formed",
                                "cawg.x509.untrusted"])
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "digitalCapture"), None, results))
    assert rec["state"] == "valid_untrusted"


def test_without_validation_results_the_flat_status_list_decides():
    store = _store(_manifest(ACTIVE, "digitalCapture"), None)
    del store["validation_results"]
    store["validation_status"] = [_code("assertion.dataHash.mismatch")]
    rec = pv.parse_manifest_store(store)
    assert rec["state"] == "invalid"
    assert rec["hard_binding_mismatch"] is True


def test_a_composite_synthetic_declaration_is_an_ai_composite():
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "compositeSynthetic",
                                                   action="c2pa.edited")))
    assert rec["dst_class"] == "ai_composite"
    assert rec["dst_action"] == "c2pa.edited"


def test_the_created_action_wins_over_a_later_one():
    m = _manifest(ACTIVE, "digitalCapture")
    m["assertions"][0]["data"]["actions"].insert(
        0, {"action": "c2pa.edited", "digitalSourceType": DST + "compositeSynthetic"})
    rec = pv.parse_manifest_store(_store(m))
    assert rec["dst_class"] == "capture"


def test_an_ai_ingredient_inside_an_edit_that_declares_nothing():
    """The edit declares no source type, so the file's own class is none; the
    generated picture it was made from is recorded as its ingredient, with its own
    declaration, signer and state."""
    child = _manifest(CHILD, "trainedAlgorithmicMedia", signer="Synthetic Generator")
    parent = _manifest(ACTIVE, ingredients=[_ingredient(CHILD)], signer="Synthetic Editor")
    deltas = [{"ingredientAssertionURI":
               f"self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3",
               "validationDeltas": {"success": [_code("ingredient.manifest.validated")],
                                    "informational": [], "failure": []}}]
    rec = pv.parse_manifest_store(_store(parent, "Valid", _results(
        failure=["signingCredential.untrusted"], deltas=deltas), others=[child]))
    assert rec["state"] == "valid_untrusted"
    assert rec["active_dst"] is None and rec["dst_class"] == "none"
    assert rec["dst_signed_valid"] is False
    [ing] = rec["ingredients"]
    assert ing["title"] == "ingredient.jpg"
    assert ing["dst"] == DST + "trainedAlgorithmicMedia"
    assert ing["dst_class"] == "generative_ai"
    assert ing["state"] == "valid_untrusted"
    assert ing["signer"]["common_name"] == "Synthetic Generator"


def test_an_ingredient_that_fails_now_is_invalid_even_if_it_validated_when_signed():
    child = _manifest(CHILD, "trainedAlgorithmicMedia")
    parent = _manifest(ACTIVE, ingredients=[_ingredient(CHILD)])
    deltas = [{"ingredientAssertionURI":
               f"self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3",
               "validationDeltas": {"success": [], "informational": [],
                                    "failure": [_code("assertion.dataHash.mismatch")]}}]
    rec = pv.parse_manifest_store(_store(parent, "Invalid", _results(deltas=deltas),
                                         others=[child]))
    assert rec["state"] == "invalid"
    assert rec["ingredients"][0]["state"] == "invalid"


def test_an_ingredient_without_a_manifest_is_absent():
    parent = _manifest(ACTIVE, ingredients=[{"title": "plain.jpg", "relationship": "parentOf"}])
    rec = pv.parse_manifest_store(_store(parent))
    assert rec["ingredients"] == [{"title": "plain.jpg", "relationship": "parentOf",
                                   "dst": None, "dst_class": "none", "state": "absent",
                                   "signer": None}]


def test_ingredients_are_followed_recursively_and_a_cycle_is_cut():
    grand = _manifest(GRANDCHILD, "trainedAlgorithmicMedia",
                      ingredients=[_ingredient(CHILD)])       # points back up
    child = _manifest(CHILD, "compositeWithTrainedAlgorithmicMedia", action="c2pa.edited",
                      ingredients=[_ingredient(GRANDCHILD)])
    parent = _manifest(ACTIVE, ingredients=[_ingredient(CHILD)])
    rec = pv.parse_manifest_store(_store(parent, others=[child, grand]))
    [c] = rec["ingredients"]
    assert c["dst_class"] == "ai_edited"
    [g] = c["ingredients"]
    assert g["dst_class"] == "generative_ai"
    [back] = g["ingredients"]
    assert back["ingredients_not_followed"] == "cycle"


def test_ingredients_stop_at_the_depth_limit():
    chain = [f"urn:c2pa:00000000-0000-4000-8000-{i:012d}" for i in range(pv.MAX_DEPTH + 3)]
    manifests = [_manifest(chain[-1], "digitalCapture")]
    for i in range(len(chain) - 2, -1, -1):
        manifests.append(_manifest(chain[i], ingredients=[_ingredient(chain[i + 1])]))
    rec = pv.parse_manifest_store(_store(manifests[-1], others=manifests[:-1]))
    depth, node = 0, rec
    while node.get("ingredients"):
        node = node["ingredients"][0]
        depth += 1
    assert depth == pv.MAX_DEPTH
    assert node["ingredients_not_followed"] == f"deeper than {pv.MAX_DEPTH}"


def test_the_record_is_json_and_carries_no_score():
    rec = pv.parse_manifest_store(_store(_manifest(ACTIVE, "trainedAlgorithmicMedia")))
    text = json.dumps(rec)
    for word in ("score", "probability", "confidence", "likelihood", "detected"):
        assert word not in text.lower()
    assert rec["state"] in pv.STATES


# -- the declared actions -------------------------------------------------------------

def _acting(actions, *, agents=None, more=(), state="Valid", failure=("signingCredential.untrusted",)):
    """A manifest declaring ``actions`` in a c2pa.actions.v2 assertion (with
    ``agents`` as its softwareAgents list), and ``more`` in a c2pa.actions one."""
    m = _manifest(ACTIVE, "digitalCapture")
    data = {"actions": list(actions)}
    if agents is not None:
        data["softwareAgents"] = list(agents)
    m["assertions"] = [{"label": "c2pa.actions.v2", "data": data}]
    if more:
        m["assertions"].append({"label": "c2pa.actions", "data": {"actions": list(more)}})
    return pv.parse_manifest_store(_store(m, state, _results(failure=failure)))


AGENTS = [{"name": "Synthetic Agent A"}, {"name": "Synthetic Indexed Agent", "version": "3.0"}]
ACTIONS = [
    {"action": "c2pa.created", "digitalSourceType": DST + "digitalCapture",
     "softwareAgent": {"name": "Synthetic Agent", "version": "2.1"}},
    {"action": "org.example.provided", "softwareAgent": "Synthetic Tool 0.9"},
    {"action": "c2pa.edited", "softwareAgentIndex": 1},
]


def test_every_declared_action_is_transcribed_with_its_software_agent():
    """A softwareAgent is a name and version, a string (actions v1) or an index into
    the assertion's softwareAgents (actions v2): the three forms c2pa-rs 0.91.0
    returns. Each is written as declared; nothing is classified."""
    rec = _acting(ACTIONS, agents=AGENTS, more=[{"action": "c2pa.opened"}])
    assert rec["actions"] == [
        {"action": "c2pa.created", "software_agent": "Synthetic Agent 2.1"},
        {"action": "org.example.provided", "software_agent": "Synthetic Tool 0.9"},
        {"action": "c2pa.edited", "software_agent": "Synthetic Indexed Agent 3.0"},
        {"action": "c2pa.opened"},
    ]
    assert "actions_omitted" not in rec
    rows = dict(pv.describe(rec))
    assert rows["Declared actions"] == (
        "c2pa.created (software agent: Synthetic Agent 2.1)\n"
        "org.example.provided (software agent: Synthetic Tool 0.9)\n"
        "c2pa.edited (software agent: Synthetic Indexed Agent 3.0)\n"
        "c2pa.opened")


def test_an_index_with_no_software_agent_behind_it_says_so():
    rec = _acting([{"action": "c2pa.edited", "softwareAgentIndex": 5}], agents=AGENTS[:1])
    assert rec["actions"] == [{"action": "c2pa.edited", "software_agent":
                               "softwareAgentIndex 5, not in the assertion's softwareAgents"}]


def test_actions_from_a_manifest_that_is_not_valid_are_marked():
    rec = _acting(ACTIONS[:1], state="Invalid",
                  failure=("signingCredential.untrusted", "assertion.dataHash.mismatch"))
    assert rec["state"] == "invalid"
    assert dict(pv.describe(rec))["Declared actions"] == (
        "not backed by a valid signature:\n"
        "c2pa.created (software agent: Synthetic Agent 2.1)")


def test_a_manifest_that_declares_no_action_says_none_declared():
    rec = _acting([])
    assert rec["actions"] == []
    assert dict(pv.describe(rec))["Declared actions"] == "none declared"


def test_a_record_read_before_actions_were_kept_does_not_read_as_none():
    rec = _acting(ACTIONS)
    del rec["actions"]
    assert dict(pv.describe(rec))["Declared actions"] == (
        "not recorded by the GLEAPP that read this file "
        "(gleapp provenance --force reads it again)")
    # a file with no manifest has no actions to speak of
    assert "Declared actions" not in dict(pv.describe(
        {"state": "absent", "active_dst": None, "dst_class": "none", "xmp_dst": None}))


def test_the_actions_kept_are_bounded_and_the_rest_counted():
    many = [{"action": f"org.example.step{i}"} for i in range(70)]
    rec = _acting(many)
    assert len(rec["actions"]) == pv.MAX_ACTIONS == 64
    assert rec["actions_omitted"] == 6
    lines = dict(pv.describe(rec))["Declared actions"].splitlines()
    assert lines[-1] == "and 6 more"
    assert len(lines) == 65


# -- the bytes ------------------------------------------------------------------------

def _jpeg(*segments: bytes) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (40, 90, 160)).save(buf, "JPEG")
    data = buf.getvalue()
    return data[:2] + b"".join(segments) + data[2:]


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload


def _xmp(dst_uri: str) -> bytes:
    return (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
            b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description '
            b'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
            b'Iptc4xmpExt:DigitalSourceType="' + dst_uri.encode() +
            b'"/></rdf:RDF></x:xmpmeta>')


def _app1_xmp(dst_uri: str) -> bytes:
    return _segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + _xmp(dst_uri))


def _app11_store() -> bytes:
    # JPEG XT: "JP", box instance, packet sequence, then a JUMBF superbox labelled c2pa
    desc = b"jumd" + bytes(16) + b"\x03c2pa\x00"
    jumb = struct.pack(">I", 8 + 4 + len(desc)) + b"jumb" + struct.pack(">I", 4 + len(desc)) + desc
    return _segment(0xEB, b"JP" + b"\x00\x01" + b"\x00\x00\x00\x01" + jumb)


def _png(*chunks: tuple[bytes, bytes]) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 20, 30)).save(buf, "PNG")
    data = buf.getvalue()
    extra = b"".join(struct.pack(">I", len(body)) + ctype + body +
                     struct.pack(">I", zlib.crc32(ctype + body)) for ctype, body in chunks)
    iend = data.rindex(b"IEND") - 4
    return data[:iend] + extra + data[iend:]


def test_a_plain_jpeg_is_read_through_and_holds_nothing(tmp_path):
    p = tmp_path / "plain.jpg"
    p.write_bytes(_jpeg())
    blocks = pv.scan_blocks(p)
    assert blocks.known and blocks.mime == "image/jpeg"
    assert blocks.stores == [] and blocks.xmp == []


def test_a_store_is_found_in_jpeg_app11_and_png_cabx(tmp_path):
    j = tmp_path / "a.bin"
    j.write_bytes(_jpeg(_app11_store()))
    assert pv.scan_blocks(j).stores == ["JPEG APP11"]
    p = tmp_path / "b.bin"
    p.write_bytes(_png((b"caBX", b"synthetic")))
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "image/png" and blocks.stores == ["PNG caBX"]


def test_the_container_is_decided_by_the_bytes_not_the_name(tmp_path):
    p = tmp_path / "looks_like.png"
    p.write_bytes(_jpeg())
    assert pv.scan_blocks(p).mime == "image/jpeg"


def test_an_xmp_source_type_is_an_unsigned_declaration(tmp_path):
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg(_app1_xmp(DST + "trainedAlgorithmicMedia")))
    decl = pv.xmp_declaration(pv.scan_blocks(p).xmp)
    assert decl == {"uri": DST + "trainedAlgorithmicMedia", "class": "generative_ai",
                    "label": "unsigned declaration",
                    "field": "XMP Iptc4xmpExt:DigitalSourceType"}


@pytest.mark.parametrize("packet", [
    b'<rdf:Description><Iptc4xmpExt:DigitalSourceType>' + DST.encode()
    + b'algorithmicMedia</Iptc4xmpExt:DigitalSourceType></rdf:Description>',
    b'<rdf:Description><Iptc4xmpExt:DigitalSourceType rdf:resource="' + DST.encode()
    + b'algorithmicMedia"/></rdf:Description>',
])
def test_the_source_type_is_read_as_an_element_too(packet):
    assert pv.xmp_declaration([packet])["class"] == "algorithmic"


def test_xmp_without_the_source_type_field_declares_nothing():
    assert pv.xmp_declaration([b"<x:xmpmeta>" + DST.encode() + b"digitalCapture</x:xmpmeta>"]) \
        is None
    assert pv.xmp_declaration([]) is None


def _box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + btype + payload


def test_a_webp_c2pa_chunk_and_xmp_chunk(tmp_path):
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(buf, "WEBP")
    raw = bytearray(buf.getvalue())
    for ctype, body in ((b"C2PA", b"synthetic store"),
                        (b"XMP ", _xmp(DST + "digitalCapture"))):
        raw += ctype + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) & 1 else b"")
    raw[4:8] = struct.pack("<I", len(raw) - 8)
    p = tmp_path / "a.webp"
    p.write_bytes(bytes(raw))
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "image/webp" and blocks.stores == ["WebP C2PA"]
    assert pv.xmp_declaration(blocks.xmp)["class"] == "capture"


def test_isobmff_c2pa_and_xmp_uuid_boxes(tmp_path):
    ftyp = _box(b"ftyp", b"isom" + bytes(4) + b"isommp42")
    c2pa = _box(b"uuid", pv._UUID_C2PA + bytes(4) + b"manifest\x00" + bytes(8))  # pylint: disable=protected-access
    xmp = _box(b"uuid", pv._UUID_XMP + _xmp(DST + "trainedAlgorithmicMedia"))  # pylint: disable=protected-access
    p = tmp_path / "clip.mp4"
    p.write_bytes(ftyp + c2pa + xmp + _box(b"mdat", bytes(64)))
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "video/mp4" and blocks.stores == ["ISOBMFF C2PA uuid box"]
    assert pv.xmp_declaration(blocks.xmp)["class"] == "generative_ai"


def test_quicktime_udta_xmp(tmp_path):
    xmp_box = _box(b"XMP_", _xmp(DST + "compositeWithTrainedAlgorithmicMedia"))
    moov = _box(b"moov", _box(b"mvhd", bytes(100)) + _box(b"udta", xmp_box))
    p = tmp_path / "clip.mov"
    p.write_bytes(_box(b"ftyp", b"qt  " + bytes(4) + b"qt  ") + moov)
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "video/quicktime" and blocks.known
    assert pv.xmp_declaration(blocks.xmp)["class"] == "ai_edited"


def test_heif_xmp_item_located_through_iloc(tmp_path):
    """A HEIF whose XMP is a 'mime' item of type application/rdf+xml, its bytes in
    mdat at the offset iloc gives."""
    xmp = _xmp(DST + "trainedAlgorithmicMedia")
    infe = _box(b"infe", bytes([2, 0, 0, 0]) + struct.pack(">HH", 1, 0) + b"mime"
                + b"\x00" + b"application/rdf+xml\x00")
    iinf = _box(b"iinf", bytes(4) + struct.pack(">H", 1) + infe)
    ftyp = _box(b"ftyp", b"heic" + bytes(4) + b"mif1heic")

    def build(offset: int) -> bytes:
        iloc = _box(b"iloc", bytes(4) + bytes([0x44, 0x00]) + struct.pack(">H", 1)
                    + struct.pack(">HHH", 1, 0, 1) + struct.pack(">II", offset, len(xmp)))
        meta = _box(b"meta", bytes(4) + _box(b"hdlr", bytes(24)) + iinf + iloc)
        return ftyp + meta

    head = build(0)
    p = tmp_path / "a.heic"
    p.write_bytes(build(len(head) + 8) + _box(b"mdat", xmp))
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "image/heic"
    assert pv.xmp_declaration(blocks.xmp)["class"] == "generative_ai"


def test_tiff_c2pa_tag_and_xmp_tag(tmp_path):
    p = tmp_path / "a.tif"
    Image.new("RGB", (8, 8), "white").save(p, "TIFF", tiffinfo={
        700: _xmp(DST + "screenCapture"), 52545: b"synthetic store"})
    blocks = pv.scan_blocks(p)
    assert blocks.mime == "image/tiff" and blocks.stores == ["TIFF tag 52545"]
    assert pv.xmp_declaration(blocks.xmp)["class"] == "screen"


def test_a_segment_cut_short_leaves_the_decision_to_the_reader(tmp_path, fake_c2pa):
    """A file that ends inside a segment the scan reads cannot be called absent from
    the bytes: what was cut off may have been a store."""
    lib = fake_c2pa(raises=lambda f: f.C2paError.ManifestNotFound("none"))
    p = tmp_path / "t.jpg"
    p.write_bytes(_jpeg(_app11_store())[:30])
    assert pv.scan_blocks(p).known is False
    assert pv.read_provenance(p)["state"] == "absent"
    assert len(lib.calls) == 1


# -- the reader, with a stand-in library ----------------------------------------------

@pytest.fixture(name="fake_c2pa")
def _fake_c2pa_fixture(monkeypatch):
    return lambda **kw: install_fake_c2pa(monkeypatch, **kw)


def test_without_the_library_every_file_is_not_checked_and_says_why(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "c2pa", None)      # import c2pa raises ImportError
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg(_app11_store(), _app1_xmp(DST + "trainedAlgorithmicMedia")))
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"] == "C2PA not checked: library unavailable"
    assert rec["library_version"] is None
    assert rec["store_in_bytes"] == "JPEG APP11"
    # the unsigned XMP declaration is still recorded, apart from the C2PA state
    assert rec["xmp_dst"] == {"uri": DST + "trainedAlgorithmicMedia", "class": "generative_ai",
                              "label": "unsigned declaration",
                              "field": "XMP Iptc4xmpExt:DigitalSourceType"}
    json.dumps(rec)


def test_a_file_with_no_store_is_absent_without_asking_the_library(tmp_path, fake_c2pa):
    lib = fake_c2pa(raises=lambda f: AssertionError("the reader must not be opened"))
    p = tmp_path / "plain.jpg"
    p.write_bytes(_jpeg())
    rec = pv.read_provenance(p)
    assert rec["state"] == "absent"
    assert rec["state_reason"] == pv.ABSENT_BY_SCAN      # says how absence was found
    assert lib.calls == []
    assert rec["library_version"] is None


def test_without_the_library_a_file_with_no_store_is_still_absent(tmp_path, monkeypatch):
    """Absence is what GLEAPP's own reading of every metadata block found; no
    signature is involved, so the library is not needed to record it."""
    monkeypatch.setitem(sys.modules, "c2pa", None)
    p = tmp_path / "plain.jpg"
    p.write_bytes(_jpeg())
    rec = pv.read_provenance(p)
    assert rec["state"] == "absent" and rec["state_reason"] == pv.ABSENT_BY_SCAN


def test_a_store_is_read_with_nothing_fetched_and_parsed(tmp_path, fake_c2pa):
    lib = fake_c2pa(store=_store(_manifest(ACTIVE, "trainedAlgorithmicMedia")))
    p = tmp_path / "g.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p)
    assert rec["state"] == "valid_untrusted"
    assert rec["dst_class"] == "generative_ai"
    [(mime, settings)] = lib.calls
    assert mime == "image/jpeg"
    assert settings["verify"] == {"remote_manifest_fetch": False, "ocsp_fetch": False}
    assert settings["core"] == {"allowed_network_hosts": [], "decode_identity_assertions": False}
    json.dumps(rec)


def _anchor(kind, body, label):
    return pv.Anchor(kind, b"-----BEGIN CERTIFICATE-----\n" + body
                     + b"\n-----END CERTIFICATE-----\n", label)


def test_the_trust_lists_used_are_recorded_and_the_one_that_vouched_named(tmp_path, fake_c2pa):
    signers = _anchor("manifest", b"A", "synthetic signer list")
    extra = _anchor("manifest", b"C", "synthetic examiner list")
    tsa = _anchor("tsa", b"B", "synthetic TSA list")
    trust = pv.TrustLists((signers, tsa, extra))
    results = _results(success=["signingCredential.trusted"], trust_uri=extra.uri)
    lib = fake_c2pa(store=_store(_manifest(ACTIVE, "digitalCapture"), "Trusted", results))
    p = tmp_path / "g.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p, trust=trust)
    assert rec["state"] == "trusted"
    assert rec["trust_lists"] == trust.describe()
    assert [(d["label"], d["passed"]) for d in rec["trust_lists"]] == [
        ("synthetic signer list", 1), ("synthetic TSA list", 1),
        ("synthetic examiner list", 1)]
    assert rec["trusted_by"] == "synthetic examiner list"
    assert rec["trust_list_sha256"] == extra.sha256
    anchors = lib.settings[0]["trust"]["anchors"]
    assert [(a["trust_kind"], a["trust_uri"]) for a in anchors] == [
        ("manifest", signers.uri), ("tsa", tsa.uri), ("manifest", extra.uri)]


def test_a_signer_trusted_through_a_tsa_anchor_is_not_trusted(tmp_path, fake_c2pa):
    tsa = _anchor("tsa", b"B", "synthetic TSA list")
    results = _results(success=["signingCredential.trusted"], trust_uri=tsa.uri)
    fake_c2pa(store=_store(_manifest(ACTIVE, "digitalCapture"), "Trusted", results))
    p = tmp_path / "g.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p, trust=pv.TrustLists((tsa,)))
    assert rec["state"] == "valid_untrusted"
    assert rec["trusted_by"] == "synthetic TSA list"


def test_a_remote_manifest_is_not_fetched(tmp_path, fake_c2pa):
    fake_c2pa(raises=lambda f: f.C2paError.RemoteManifest("remote"))
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description '
           b'xmlns:dcterms="http://purl.org/dc/terms/" '
           b'dcterms:provenance="https://example.invalid/manifest.c2pa"/></rdf:RDF></x:xmpmeta>')
    p = tmp_path / "r.jpg"
    p.write_bytes(_jpeg(_segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp)))
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"] == "remote manifest not fetched (offline)"
    assert rec["remote_url"] == "https://example.invalid/manifest.c2pa"


def test_a_store_the_library_cannot_parse_is_malformed_and_names_no_path(tmp_path, fake_c2pa):
    p = tmp_path / "evidence folder" / "m.jpg"
    p.parent.mkdir()
    fake_c2pa(raises=lambda f: f.C2paError(f"JumbfParseError in {p}"))
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p)
    assert rec["state"] == "malformed"
    assert str(tmp_path) not in rec["state_reason"]
    assert "JumbfParseError" in rec["state_reason"]


@pytest.mark.parametrize("error, reason", [
    ("NotSupported", "C2PA not checked: the c2pa reader does not support this format"),
    ("Io", "C2PA not checked: the c2pa reader could not read the file"),
    ("FileNotFound", "C2PA not checked: the c2pa reader could not read the file"),
])
def test_a_reader_failure_that_says_nothing_about_the_manifest_is_not_checked(
        tmp_path, fake_c2pa, error, reason):
    """Only a failure about the manifest itself makes it malformed: a format the
    reader does not take, or a file it could not read, leaves it not checked."""
    fake_c2pa(raises=lambda f: getattr(f.C2paError, error)("synthetic"))
    p = tmp_path / "m.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"].startswith(reason)


def test_any_other_reader_failure_is_not_checked(tmp_path, fake_c2pa):
    fake_c2pa(raises=lambda f: MemoryError("synthetic"))
    p = tmp_path / "m.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"].startswith("reader error: MemoryError")


def test_a_file_that_cannot_be_opened_is_not_checked(tmp_path):
    rec = pv.read_provenance(tmp_path / "gone.jpg")
    assert rec["state"] == "not_checked"
    assert rec["state_reason"].startswith("file could not be read")
    assert str(tmp_path) not in rec["state_reason"]


def test_the_file_is_never_written(tmp_path, fake_c2pa):
    fake_c2pa(store=_store(_manifest(ACTIVE, "digitalCapture")))
    p = tmp_path / "g.jpg"
    data = _jpeg(_app11_store())
    p.write_bytes(data)
    stat = p.stat()
    pv.read_provenance(p)
    assert p.read_bytes() == data
    assert p.stat().st_mtime_ns == stat.st_mtime_ns
    assert sorted(x.name for x in tmp_path.iterdir()) == ["g.jpg"]


def test_a_c2pa_library_in_the_working_directory_is_refused(tmp_path, monkeypatch):
    """c2pa-python loads the first native library it finds, and the working directory
    comes before its own folder; the control shows the check is what refuses it."""
    monkeypatch.delitem(sys.modules, "c2pa", raising=False)
    monkeypatch.chdir(tmp_path)
    name = pv._C2PA_LIBRARY.get(sys.platform, "libc2pa_c.so")  # pylint: disable=protected-access
    # the control: nothing planted yet
    assert pv._planted_c2pa_library() is False                 # pylint: disable=protected-access
    (tmp_path / "libs" / "x86_64").mkdir(parents=True)
    (tmp_path / "libs" / "x86_64" / name).write_bytes(b"not a library")
    assert pv._planted_c2pa_library() is True                  # pylint: disable=protected-access
    (tmp_path / "libs" / "x86_64" / name).unlink()
    (tmp_path / name).write_bytes(b"not a library")
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg(_app11_store()))
    rec = pv.read_provenance(p)
    assert rec["state"] == "not_checked"
    assert rec["state_reason"] == pv.PLANTED


def test_the_reader_settings_fetch_nothing_and_load_both_lists():
    s = pv.reader_settings(None)
    assert s["verify"] == {"remote_manifest_fetch": False, "ocsp_fetch": False}
    assert s["core"]["allowed_network_hosts"] == []
    assert s["trust"]["anchors"] == []
    # c2pa-rs's own EKU list, the C2PA claim-signing EKU among them
    assert s["trust"]["trust_config"].split() == list(pv.VALID_EKUS)
    assert "1.3.6.1.4.1.62558.2.1" in pv.VALID_EKUS
    t = pv.TrustLists((_anchor("manifest", b"S", "s"), _anchor("tsa", b"T", "t")))
    kinds = [a["trust_kind"] for a in pv.reader_settings(t)["trust"]["anchors"]]
    assert kinds == ["manifest", "tsa"]


def test_the_caveat_is_the_fixed_text():
    assert pv.CAVEAT == (
        "Content Credentials record what the signer declared. A valid signature shows the "
        "credentials were not changed after signing; who signed is established only when "
        "the signer's certificate is on a trust list GLEAPP holds (trusted). An AI source "
        "type is a declaration, not a finding. Absence of credentials does not indicate "
        "authenticity: many platforms and tools remove them.")


def test_the_module_imports_no_network_library():
    src = Path(pv.__file__).read_text(encoding="utf-8")
    for mod in ("urllib", "requests", "http.client", "socket"):
        assert f"import {mod}" not in src and f"from {mod}" not in src
