"""Content Credentials read during processing, and by a pass that can be run again.

Processing reads each picture's and video's metadata blocks itself, on the bytes it is
already holding (``local``: the file, or the copy pulled out of a zip or an image read
in place), and settles every file that holds no manifest store there. Only a file that
holds one goes on to the c2pa reader, which runs in a child process, a batch at a
time, the way video decoding does: a native fault in it costs a file, not the run.
A case processed before this existed keeps NULL in the four columns, which means
"not read yet", until the examiner runs the pass (``gleapp provenance`` or the
gallery's button); processing does not start reading a whole old case on its own.
"""

import io
import json
import struct
import sys
import time
import zipfile
from pathlib import Path

import pytest
from PIL import Image

from gleapp import provenance as pv
from gleapp.case import Source, open_case
from gleapp.db import SCHEMA_VERSION, CaseDB
from gleapp.pipeline import ingest_sources, process, provenance_pass

DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"
COLUMNS = ("c2pa_state", "c2pa_dst_class", "c2pa_signer", "c2pa_info")


@pytest.fixture(autouse=True)
def _isolate_appconfig(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("GLEAPP_CONFIG_DIR", str(tmp_path_factory.mktemp("gleapp-cfg")))
    from gleapp import hashstore, stash  # pylint: disable=import-outside-toplevel
    hashstore.close()
    stash.close()
    yield
    hashstore.close()
    stash.close()


def _jpeg(*segments: bytes, color=(40, 90, 160)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), color).save(buf, "JPEG")
    data = buf.getvalue()
    return data[:2] + b"".join(segments) + data[2:]


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload


def _xmp_dst(term: str) -> bytes:
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description '
           b'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
           b'Iptc4xmpExt:DigitalSourceType="' + DST.encode() + term.encode() +
           b'"/></rdf:RDF></x:xmpmeta>')
    return _segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp)


def _store_stub() -> bytes:
    """A JPEG XT APP11 segment that looks like a C2PA store to the byte scan; no
    reader can validate it."""
    desc = b"jumd" + bytes(16) + b"\x03c2pa\x00"
    jumb = struct.pack(">I", 12 + len(desc)) + b"jumb" + struct.pack(">I", 4 + len(desc)) + desc
    return _segment(0xEB, b"JP\x00\x01\x00\x00\x00\x01" + jumb)


def _folder(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "plain.jpg").write_bytes(_jpeg())
    (ev / "declared.jpg").write_bytes(_jpeg(_xmp_dst("trainedAlgorithmicMedia"), color=(9, 9, 9)))
    (ev / "stub.jpg").write_bytes(_jpeg(_store_stub(), color=(200, 10, 10)))
    return ev


def _rows(case) -> dict:
    return {r["rel_path"]: r for r in case.db.iter_files("kind IN ('image','video')")}


def _no_library(monkeypatch):
    monkeypatch.setitem(sys.modules, "c2pa", None)


# -- the schema -----------------------------------------------------------------------

def test_an_old_case_gains_the_columns_empty_and_the_new_schema_version(tmp_path):
    db = CaseDB(tmp_path / "case.gleapp")
    db.upsert_file(str(tmp_path / "a.jpg"), rel_path="a.jpg", source="s", kind="image",
                   ext=".jpg", size=1, mtime=0.0)
    db.conn.execute("DROP INDEX idx_files_c2pa_state")
    for col in COLUMNS:
        db.conn.execute(f"ALTER TABLE files DROP COLUMN {col}")
    db.conn.execute("UPDATE meta SET value='18' WHERE key='schema_version'")
    db.conn.commit()
    db.close()
    db2 = CaseDB(tmp_path / "case.gleapp")
    try:
        assert SCHEMA_VERSION == 19
        assert db2.get_meta("schema_version") == "19"
        row = db2.iter_files()[0]
        assert all(row[c] is None for c in COLUMNS)       # NULL: not read yet
        indexes = {r["name"] for r in db2.conn.execute("PRAGMA index_list(files)")}
        assert "idx_files_c2pa_state" in indexes
    finally:
        db2.close()


# -- processing -----------------------------------------------------------------------

def test_processing_settles_what_the_bytes_can_and_leaves_the_rest_to_the_reader(
        tmp_path, monkeypatch):
    _no_library(monkeypatch)
    case = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        ingest_sources(case, [Source(name="ev", path=str(_folder(tmp_path)))])
        stats = process(case, workers=1, screen=False, similar=False)
        rows = _rows(case)
        assert rows["plain.jpg"]["c2pa_state"] == "absent"
        assert rows["plain.jpg"]["c2pa_dst_class"] == "none"
        declared = json.loads(rows["declared.jpg"]["c2pa_info"])
        assert rows["declared.jpg"]["c2pa_state"] == "absent"
        assert rows["declared.jpg"]["c2pa_dst_class"] == "none"     # never folded in
        assert declared["xmp_dst"]["label"] == "unsigned declaration"
        assert declared["xmp_dst"]["class"] == "generative_ai"
        stub = json.loads(rows["stub.jpg"]["c2pa_info"])
        assert rows["stub.jpg"]["c2pa_state"] == "not_checked"
        assert stub["state_reason"] == pv.NOT_CHECKED_LIBRARY
        assert stub["store_in_bytes"] == "JPEG APP11"
        assert stats.stages["provenance"].startswith("ok")
    finally:
        case.close()


def test_a_file_that_will_not_decode_still_has_its_credentials_read(tmp_path, monkeypatch):
    _no_library(monkeypatch)
    ev = tmp_path / "evidence"
    ev.mkdir()
    seg = _xmp_dst("digitalCapture")
    (ev / "cut.jpg").write_bytes(_jpeg(seg)[:2 + len(seg) + 120])   # cut after the XMP
    case = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        ingest_sources(case, [Source(name="ev", path=str(ev))])
        process(case, workers=1, screen=False, similar=False)
        row = _rows(case)["cut.jpg"]
        assert row["error"]
        assert row["c2pa_state"] is not None
        assert json.loads(row["c2pa_info"])["xmp_dst"]["class"] == "capture"
    finally:
        case.close()


def test_processing_assigns_no_category(tmp_path, monkeypatch):
    _no_library(monkeypatch)
    case = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        ingest_sources(case, [Source(name="ev", path=str(_folder(tmp_path)))])
        before = [tuple(r) for r in case.db.conn.execute("SELECT id, category FROM files")]
        process(case, workers=1, screen=False, similar=False)
        after = [tuple(r) for r in case.db.conn.execute("SELECT id, category FROM files")]
        assert before == after
    finally:
        case.close()


# -- the pass -------------------------------------------------------------------------

def _old_case(tmp_path, monkeypatch):
    """A processed case whose rows were never read, as an older build leaves it."""
    _no_library(monkeypatch)
    case = open_case(tmp_path / "case", create=True, examiner="t")
    ingest_sources(case, [Source(name="ev", path=str(_folder(tmp_path)))])
    process(case, workers=1, screen=False, similar=False)
    case.db.conn.execute("UPDATE files SET c2pa_state=NULL, c2pa_dst_class=NULL, "
                         "c2pa_signer=NULL, c2pa_info=NULL")
    case.db.commit()
    return case


def test_processing_does_not_start_reading_an_old_case_on_its_own(tmp_path, monkeypatch):
    case = _old_case(tmp_path, monkeypatch)
    try:
        process(case, workers=1, screen=False, similar=False)
        assert all(r["c2pa_state"] is None for r in _rows(case).values())
    finally:
        case.close()


def test_the_pass_reads_what_was_never_read_and_then_nothing(tmp_path, monkeypatch):
    case = _old_case(tmp_path, monkeypatch)
    try:
        counts = provenance_pass(case)
        assert counts["read"] == 3
        assert counts["states"] == {"absent": 2, "not_checked": 1}
        assert {r["c2pa_state"] for r in _rows(case).values()} == {"absent", "not_checked"}
        # not_checked is read again, since its reason (no library) may have gone
        again = provenance_pass(case)
        assert again["read"] == 1 and again["states"] == {"not_checked": 1}
        assert provenance_pass(case, retry=False)["read"] == 0
        assert provenance_pass(case, force=True)["read"] == 3
        entries = [r for r in case.db.conn.execute(
            "SELECT action, detail FROM audit WHERE action = 'provenance'")]
        assert len(entries) == 4
        detail = json.loads(entries[0]["detail"])
        assert detail["states"] == {"absent": 2, "not_checked": 1}
        assert "trust_lists" in detail and "library" in detail
    finally:
        case.close()


def test_the_pass_reads_a_zip_in_place_and_never_writes_to_it(tmp_path, monkeypatch):
    _no_library(monkeypatch)
    z = tmp_path / "extraction.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("Dump/DCIM/declared.jpg", _jpeg(_xmp_dst("screenCapture")))
        zf.writestr("Dump/DCIM/stub.jpg", _jpeg(_store_stub()))
    before = (z.read_bytes(), z.stat().st_mtime_ns)
    case = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        ingest_sources(case, [Source(name="zip", path=str(z), kind="archive")])
        process(case, workers=1, screen=False, similar=False)
        rows = {r["rel_path"].split("/")[-1]: r for r in _rows(case).values()}
        assert json.loads(rows["declared.jpg"]["c2pa_info"])["xmp_dst"]["class"] == "screen"
        assert rows["stub.jpg"]["c2pa_state"] == "not_checked"
        assert provenance_pass(case, force=True)["read"] == 2
        assert (z.read_bytes(), z.stat().st_mtime_ns) == before
        # what the pass pulled out of the zip went under the case and is gone again
        assert not any((case.root / "tmp").glob("**/*.jpg"))
    finally:
        case.close()


def test_a_trust_list_that_cannot_be_read_stops_the_pass_and_leaves_rows_unread(
        tmp_path, monkeypatch):
    from gleapp import appconfig  # pylint: disable=import-outside-toplevel
    case = _old_case(tmp_path, monkeypatch)
    monkeypatch.delitem(sys.modules, "c2pa")
    monkeypatch.setattr(pv, "library_available", lambda: (True, None))
    appconfig.set_c2pa_trust_lists(signer_anchors=str(tmp_path / "gone.pem"))
    try:
        with pytest.raises(pv.TrustListError):
            provenance_pass(case)
        assert _rows(case)["stub.jpg"]["c2pa_state"] is None
    finally:
        case.close()


# -- the reader process ---------------------------------------------------------------

def test_signed_files_are_read_by_the_reader_process_during_processing(tmp_path):
    """With the optional library: a signed picture and a signed clip go through the
    reader stage, in its child process, and land in the columns."""
    pytest.importorskip("c2pa")
    cv2 = pytest.importorskip("cv2")
    import numpy as np  # pylint: disable=import-outside-toplevel
    from c2pasign import created, make_chain, sign  # pylint: disable=import-error,import-outside-toplevel
    chain = make_chain()
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "generated.jpg").write_bytes(
        sign(chain, _jpeg(), "image/jpeg", created("trainedAlgorithmicMedia")))
    raw = tmp_path / "raw.mp4"
    writer = cv2.VideoWriter(str(raw), cv2.VideoWriter_fourcc(*"mp4v"), 10, (64, 48))
    for i in range(10):
        writer.write(np.full((48, 64, 3), i * 20, np.uint8))
    writer.release()
    (ev / "clip.mp4").write_bytes(
        sign(chain, raw.read_bytes(), "video/mp4", created("digitalCapture")))
    (ev / "plain.jpg").write_bytes(_jpeg(color=(1, 2, 3)))
    case = open_case(tmp_path / "case", create=True, examiner="t")
    try:
        ingest_sources(case, [Source(name="ev", path=str(ev))])
        stats = process(case, workers=1, screen=False, similar=False)
        assert stats.stages["provenance"] == "ok: 2 read by the c2pa reader"
        rows = _rows(case)
        gen, clip = rows["generated.jpg"], rows["clip.mp4"]
        assert (gen["c2pa_state"], gen["c2pa_dst_class"]) == ("valid_untrusted", "generative_ai")
        assert gen["c2pa_signer"] == "Synthetic Signer (Synthetic Test Org)"
        assert (clip["c2pa_state"], clip["c2pa_dst_class"]) == ("valid_untrusted", "capture")
        info = json.loads(gen["c2pa_info"])
        assert info["library_version"].startswith("c2pa-python 0.38")
        assert info["trust_lists"][0]["label"].startswith("C2PA Trust List (bundled")
        assert rows["plain.jpg"]["c2pa_state"] == "absent"
    finally:
        case.close()


def test_a_reader_that_dies_costs_the_file_it_died_on(tmp_path, monkeypatch):
    """The worker is replaced by one that exits on the file named 'poison', after
    answering for nothing; the batch is split until that file is alone, and only
    it is recorded as stopping the reader."""
    names = ["a.jpg", "b.jpg", "poison.jpg", "c.jpg"]
    paths = []
    for n in names:
        p = tmp_path / n
        p.write_bytes(_jpeg(_store_stub()))
        paths.append(str(p))
    fake = tmp_path / "fake_worker.py"
    fake.write_text(
        "import json, sys\n"
        "req = json.load(sys.stdin)\n"
        "if any('poison' in i['path'] for i in req['items']):\n"
        "    sys.exit(134)\n"
        "for i in req['items']:\n"
        "    print(json.dumps({'path': i['path'], 'outcome': {'kind': 'absent'}}), flush=True)\n",
        encoding="utf-8")
    monkeypatch.setattr(pv, "worker_command", lambda: [sys.executable, str(fake)])
    monkeypatch.setattr(pv, "library_available", lambda: (True, None))
    out = pv.read_batch(paths, trust=pv.TrustLists())
    states = {Path(p).name: r["state"] for p, r in out.items()}
    assert states == {"a.jpg": "absent", "b.jpg": "absent", "poison.jpg": "not_checked",
                      "c.jpg": "absent"}
    poisoned = next(r for p, r in out.items() if "poison" in p)
    assert poisoned["state_reason"] == pv.READER_STOPPED


def test_the_reader_process_is_handed_no_path_on_its_command_line(tmp_path, monkeypatch):
    """The paths and the trust anchors go to the child on stdin, so nothing about the
    evidence sits in a temporary file or in the process list."""
    seen = {}
    import subprocess  # pylint: disable=import-outside-toplevel
    real = subprocess.run

    def spy(cmd, *args, **kwargs):
        seen["cmd"], seen["input"] = cmd, kwargs.get("input")
        # the caller's own check= arrives in kwargs
        return real(cmd, *args, **kwargs)  # pylint: disable=subprocess-run-check

    p = tmp_path / "s.jpg"
    p.write_bytes(_jpeg(_store_stub()))
    monkeypatch.setattr(subprocess, "run", spy)
    monkeypatch.setattr(pv, "library_available", lambda: (True, None))
    pv.read_batch([str(p)], trust=pv.TrustLists())
    assert str(p) not in " ".join(seen["cmd"])
    assert [i["path"] for i in json.loads(seen["input"])["items"]] == [str(p)]


# -- the command line and the gallery -------------------------------------------------

def test_the_command_line_runs_the_pass(tmp_path, monkeypatch, capsys):
    from gleapp import cli  # pylint: disable=import-outside-toplevel
    case = _old_case(tmp_path, monkeypatch)
    root = case.root
    case.close()
    assert cli.main(["-c", str(root), "provenance"]) == 0
    out = capsys.readouterr().out
    assert "3 file(s) read" in out and "absent: 2" in out and "not_checked: 1" in out
    reopened = open_case(root)
    try:
        assert all(r["c2pa_state"] for r in _rows(reopened).values())
    finally:
        reopened.close()


def test_the_command_line_takes_trust_lists_for_one_run(tmp_path, monkeypatch, capsys):
    from gleapp import cli  # pylint: disable=import-outside-toplevel
    case = _old_case(tmp_path, monkeypatch)
    root = case.root
    case.close()
    bad = tmp_path / "notes.txt"
    bad.write_text("no certificate", encoding="utf-8")
    monkeypatch.delitem(sys.modules, "c2pa")
    monkeypatch.setattr(pv, "library_available", lambda: (True, None))
    assert cli.main(["-c", str(root), "provenance", "--trust-anchors", str(bad)]) == 2
    assert "no PEM certificate" in capsys.readouterr().err


def test_the_gallery_runs_the_pass_as_a_job(tmp_path, monkeypatch):
    from gleapp.web.app import create_app  # pylint: disable=import-outside-toplevel
    case = _old_case(tmp_path, monkeypatch)
    root = case.root
    case.close()
    app = create_app(str(root))
    cl = app.test_client()
    before = cl.get("/api/context").get_json()["provenance"]
    assert before["unread"] == 3 and before["library"] is False
    assert sum(before["states"].values()) == 0
    assert cl.post("/api/provenance", json={}).get_json() == {"ok": True}
    for _ in range(240):
        job = cl.get("/api/job").get_json()
        if not job["running"]:
            break
        time.sleep(0.25)
    assert job["stage"] == "done", job
    assert job["stats"]["read"] == 3
    assert job["stats"]["states"] == {"absent": 2, "not_checked": 1}
    after = cl.get("/api/context").get_json()["provenance"]
    assert after["unread"] == 0
    assert after["states"] == {"absent": 2, "malformed": 0, "invalid": 0,
                               "valid_untrusted": 0, "trusted": 0, "not_checked": 1}
