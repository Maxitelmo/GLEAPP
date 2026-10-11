"""The manual, the in-app help and the README say what gleapp/provenance.py does.

The caveat is printed by every surface that explains Content Credentials, so the two
manuals carry it word for word; the vocabulary they list is the module's; and nothing
describes the reading as finding anything about the content.
"""

import html
import re
from pathlib import Path

from gleapp import provenance as pv

REPO = Path(__file__).resolve().parents[1]


def _flat(text: str) -> str:
    return " ".join(text.split())


def _manual() -> str:
    return (REPO / "docs/MANUAL.md").read_text(encoding="utf-8")


def _help() -> str:
    return (REPO / "gleapp/web/static/help.html").read_text(encoding="utf-8")


def test_both_manuals_carry_the_caveat_word_for_word():
    manual = _flat(_manual().replace("> ", ""))
    assert pv.CAVEAT in manual
    plain = _flat(html.unescape(re.sub(r"<[^>]+>", "", _help())))
    assert pv.CAVEAT in plain


def test_both_manuals_list_every_state_and_every_source_type_term():
    for doc in (_manual(), html.unescape(_help())):
        for label in pv.STATE_LABELS.values():
            assert label in doc, label
        for cls, terms in pv._DST_GROUPS.items():  # pylint: disable=protected-access
            assert pv.DST_CLASS_LABELS[cls] in doc, cls
            for term in terms:
                assert term in doc, term


def test_both_manuals_mark_each_term_iptc_has_retired():
    for doc in (_manual(), html.unescape(_help())):
        for term in pv.RETIRED_TERMS:
            assert any(term in ln and "retired by IPTC" in ln
                       for ln in doc.splitlines()), term


def test_neither_manual_gives_one_cause_for_a_hard_binding_that_does_not_match():
    plain = _flat(html.unescape(re.sub(r"<[^>]+>", "", _help())))
    for doc in (_flat(_manual()), plain):
        assert "the file changed after signing" not in doc
        assert "no longer matches the bytes" not in doc
        assert ("does not match the content the manifest was signed for: for example, "
                "the content changed after signing, or the manifest belongs to other "
                "content") in doc


def test_the_help_page_links_its_new_section():
    page = _help()
    assert '<h2 id="c2pa">20. Content Credentials (C2PA) and source type</h2>' in page
    assert '<a href="#c2pa">20. Content Credentials (C2PA)</a>' in page
    assert '<h2 id="credits">21. Credits &amp; acknowledgments</h2>' in page


def test_the_readme_row_does_not_call_it_detection():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines()
               if line.startswith("| **Content Credentials** |"))
    assert "detect" not in row.lower()
    assert "performs **no** content classification" in readme


def test_the_command_line_flags_the_manual_names_exist():
    from gleapp import cli  # pylint: disable=import-outside-toplevel
    sub = next(a for a in cli.build_parser()._actions  # pylint: disable=protected-access
               if a.dest == "func" or getattr(a, "choices", None) and "provenance" in a.choices)
    flags = {o for a in sub.choices["provenance"]._actions  # pylint: disable=protected-access
             for o in a.option_strings}
    for flag in ("--force", "--trust-anchors", "--tsa-anchors", "--c2pa-trust-list",
                 "--c2pa-tsa-trust-list"):
        assert flag in flags, flag
        assert flag in _manual(), flag
