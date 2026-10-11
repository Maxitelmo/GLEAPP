"""A case reads the same declarations when the source-type vocabulary changes.

What a file declares is a URI, and every record keeps it (``active_dst``, each
ingredient's ``dst``, ``xmp_dst.uri``). The class beside it is worked out from that
URI, so when a build moves a term to another class:

* ``files.c2pa_info`` is never rewritten: it stays the record as it was read;
* ``provenance.load`` works each class out again from its URI, so every surface that
  reads a record (details pane, reports, exports) shows this build's class;
* ``files.c2pa_dst_class``, which the filter and the list read, is worked out again
  once, when the case is opened, for each ``provenance.DST_VOCABULARY``.

The stale classes here are written by hand: they stand for what an older build
decided under an older vocabulary.
"""

import json

import pytest
from PIL import Image

from gleapp import provenance as pv
from gleapp.case import Source, open_case
from gleapp.pipeline import ingest_sources

# a fixture argument shadows the fixture function, as everywhere else in this suite
# pylint: disable=redefined-outer-name

DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"
GENERATED = DST + "trainedAlgorithmicMedia"
CAPTURED = DST + "digitalCapture"


def _stale_record() -> dict:
    """A record whose classes all disagree with their URIs, ingredients nested."""
    return {
        "state": "valid_untrusted", "codes": {}, "signer": None,
        "active_dst": GENERATED, "dst_class": "capture",
        "ingredients": [{"title": "a.jpg", "dst": CAPTURED, "dst_class": "generative_ai",
                         "state": "valid_untrusted", "signer": None,
                         "ingredients": [{"title": "b.jpg", "dst": GENERATED,
                                          "dst_class": "screen", "state": "absent",
                                          "signer": None}]},
                        {"title": "c.jpg", "dst": None, "dst_class": "capture",
                         "state": "absent", "signer": None}],
        "xmp_dst": {"uri": CAPTURED, "class": "generative_ai", "label": pv.UNSIGNED},
    }


def test_load_works_each_class_out_again_from_its_uri():
    stored = json.dumps(_stale_record(), sort_keys=True)
    rec = pv.load(stored)
    assert rec["dst_class"] == "generative_ai"
    assert rec["ingredients"][0]["dst_class"] == "capture"
    assert rec["ingredients"][0]["ingredients"][0]["dst_class"] == "generative_ai"
    assert rec["ingredients"][1]["dst_class"] == "none"
    assert rec["xmp_dst"]["class"] == "capture"
    # everything else is as stored
    stale = json.loads(stored)
    assert rec["active_dst"] == stale["active_dst"]
    assert rec["xmp_dst"]["uri"] == stale["xmp_dst"]["uri"]
    assert rec["state"] == stale["state"]


def test_what_a_surface_shows_follows_the_uri():
    text = pv.describe_text(pv.load(json.dumps(_stale_record(), sort_keys=True)))
    assert "trainedAlgorithmicMedia (Generative AI)" in text
    assert "a.jpg: digitalCapture (Capture)" in text
    assert "digitalCapture (Capture), unsigned declaration" in text
    assert pv.xmp_text(pv.load(json.dumps(_stale_record()))).startswith("capture ")


def test_a_record_without_classes_loads_as_it_was():
    for rec in ({"state": "not_checked"}, {"state": "absent", "xmp_dst": None}):
        assert pv.load(json.dumps(rec)) == rec


@pytest.fixture
def case_root(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    for i, name in enumerate(("generated.jpg", "plain.jpg")):
        Image.new("RGB", (16, 16), (40 * i, 80, 120)).save(ev / name, "JPEG")
    c = open_case(tmp_path / "case", create=True, examiner="t")
    ingest_sources(c, [Source(name="ev", path=str(ev))])
    ids = {r["rel_path"]: r["id"] for r in c.db.iter_files()}
    stale = _stale_record()
    c.db.update_file(ids["generated.jpg"], **pv.columns(stale))
    absent = {"state": "absent", "active_dst": None, "dst_class": "none", "xmp_dst": None}
    c.db.update_file(ids["plain.jpg"], **pv.columns(absent))
    c.db.commit()
    # as an older build left it: a class decided under another vocabulary
    c.db.conn.execute("DELETE FROM meta WHERE key = 'c2pa_dst_vocabulary'")
    c.db.commit()
    c.close()
    return tmp_path / "case", ids


def test_a_virtual_recording_read_as_an_ai_composite_is_no_longer_one(case_root):
    """Vocabulary 1 put virtualRecording under "Composite with AI"."""
    root, ids = case_root
    record = {"state": "valid_untrusted", "codes": {}, "signer": None,
              "active_dst": DST + "virtualRecording", "dst_class": "ai_composite",
              "ingredients": [], "xmp_dst": None}
    c = open_case(root)
    try:
        c.db.update_file(ids["generated.jpg"], **pv.columns(record))
        c.db.set_meta("c2pa_dst_vocabulary", "1")
        c.db.commit()
    finally:
        c.close()
    assert _column(root, ids["generated.jpg"])[0] == "virtual_recording"
    stored = json.dumps(record, sort_keys=True)
    assert _column(root, ids["generated.jpg"])[1] == stored
    assert pv.load(stored)["dst_class"] == "virtual_recording"


@pytest.mark.parametrize("term, cls", [("composite", "composite"),
                                       ("compositeCapture", "composite_capture"),
                                       ("algorithmicallyEnhanced", "algorithmically_altered")])
def test_a_term_read_as_a_human_edit_is_no_longer_one(case_root, term, cls):
    """Vocabularies 1 and 2 put these under "Human edits"."""
    root, ids = case_root
    record = {"state": "valid_untrusted", "codes": {}, "signer": None,
              "active_dst": DST + term, "dst_class": "human_edit",
              "ingredients": [], "xmp_dst": None}
    c = open_case(root)
    try:
        c.db.update_file(ids["generated.jpg"], **pv.columns(record))
        c.db.set_meta("c2pa_dst_vocabulary", "2")
        c.db.commit()
    finally:
        c.close()
    assert _column(root, ids["generated.jpg"])[0] == cls
    assert pv.load(json.dumps(record))["dst_class"] == cls


def test_a_new_case_starts_on_this_vocabulary(tmp_path):
    c = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        assert c.db.get_meta("c2pa_dst_vocabulary") == str(pv.DST_VOCABULARY)
    finally:
        c.close()


def _column(root, file_id):
    c = open_case(root)
    try:
        row = c.db.conn.execute("SELECT c2pa_dst_class, c2pa_info FROM files WHERE id = ?",
                                (file_id,)).fetchone()
        return row["c2pa_dst_class"], row["c2pa_info"], c.db.get_meta("c2pa_dst_vocabulary")
    finally:
        c.close()


def _set_column(root, file_id, value):
    c = open_case(root)
    try:
        c.db.conn.execute("UPDATE files SET c2pa_dst_class = ? WHERE id = ?", (value, file_id))
        c.db.commit()
    finally:
        c.close()


def test_opening_a_case_works_the_column_out_again(case_root):
    root, ids = case_root
    stored = json.dumps(_stale_record(), sort_keys=True)
    cls, info, vocabulary = _column(root, ids["generated.jpg"])
    assert cls == "generative_ai"
    assert info == stored                    # the record is never rewritten
    assert vocabulary == str(pv.DST_VOCABULARY)
    assert _column(root, ids["plain.jpg"])[0] == "none"


def test_the_column_is_worked_out_once_per_vocabulary(case_root, monkeypatch):
    root, ids = case_root
    assert _column(root, ids["generated.jpg"])[0] == "generative_ai"
    # a later open under the same vocabulary reads nothing again
    _set_column(root, ids["generated.jpg"], "capture")
    assert _column(root, ids["generated.jpg"])[0] == "capture"
    # a build with another vocabulary works it out again
    monkeypatch.setattr(pv, "DST_VOCABULARY", pv.DST_VOCABULARY + 1)
    cls, _info, vocabulary = _column(root, ids["generated.jpg"])
    assert cls == "generative_ai"
    assert vocabulary == str(pv.DST_VOCABULARY)


def test_the_filter_finds_a_row_by_the_class_its_uri_has(case_root):
    root, _ids = case_root
    from gleapp.web.app import create_app  # pylint: disable=import-outside-toplevel
    cl = create_app(str(root)).test_client()
    got = cl.get("/api/files?limit=50&c2pa_dst=generative_ai").get_json()
    assert {f["rel_path"] for f in got["files"]} == {"generated.jpg"}
    assert cl.get("/api/files?limit=50&c2pa_dst=capture").get_json()["files"] == []
