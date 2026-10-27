"""The gallery in another language (gleapp/i18n.py, gleapp/web/static/i18n.js).

A translation is a catalog keyed by the English the page shows, applied in the page, so
what can go wrong is in the catalog (a placeholder the page never fills, a translation
that is itself another key) and in the plumbing (which language a request gets, where
the choice is kept, the page loading the catalog before app.js). Evidence must never be
translated, so the places that show it are checked for translate="no".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from gleapp import appconfig, i18n

STATIC = Path(i18n.__file__).parent / "web" / "static"
TEMPLATE = Path(i18n.__file__).parent / "web" / "templates" / "index.html"
KEY_PH = re.compile(r"\{([a-z][a-z0-9_]*)(:t)?\}")
OUT_PH = re.compile(r"\{([a-z][a-z0-9_]*)(\?[^{}]*)?\}")


def _catalogs():
    return sorted((STATIC / "i18n").glob("*.json"))


@pytest.fixture(autouse=True)
def _own_config(tmp_path, monkeypatch):
    # the language is an app-wide setting; each test starts with none chosen
    monkeypatch.setenv("GLEAPP_CONFIG_DIR", str(tmp_path / "cfg"))


def _client():
    from gleapp.web.app import create_app              # pylint: disable=import-outside-toplevel
    return create_app(None).test_client()


def _served(cl, **headers) -> dict:
    r = cl.get("/i18n.js", headers=headers)
    assert r.status_code == 200
    assert r.mimetype == "application/javascript"
    assert r.headers["Cache-Control"] == "no-store"
    body = r.get_data(as_text=True)
    prefix = "window.GLEAPP_I18N = "
    assert body.startswith(prefix)
    return json.loads(body[len(prefix):].strip().rstrip(";"))


def test_there_is_a_spanish_catalog_and_english_needs_none():
    assert [p.stem for p in _catalogs()] == ["es"]
    assert i18n.languages() == {"en": "English", "es": "Español"}
    assert i18n.messages("en") == {}
    assert len(i18n.messages("es")) > 1000


@pytest.mark.parametrize("path", _catalogs(), ids=lambda p: p.stem)
def test_a_catalog_is_text_to_text(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == {"name", "messages"}
    assert isinstance(data["name"], str) and data["name"]
    for key, out in data["messages"].items():
        assert isinstance(key, str) and key.strip(), key
        assert isinstance(out, str) and out.strip(), key


@pytest.mark.parametrize("path", _catalogs(), ids=lambda p: p.stem)
def test_every_placeholder_a_translation_uses_is_one_its_key_fills(path):
    """A placeholder the key does not fill would reach the screen as "{name}"; one the
    translation drops loses a number or a name, except an English plural ending ("s"),
    which a language with other plurals writes its own way."""
    bad = []
    for key, out in json.loads(path.read_text(encoding="utf-8"))["messages"].items():
        filled = {m.group(1) for m in KEY_PH.finditer(key)}
        used = {m.group(1) for m in OUT_PH.finditer(out)}
        if used - filled or (filled - used) - i18n.PLURAL_ENDINGS:
            bad.append((key, sorted(filled), sorted(used)))
    assert not bad


@pytest.mark.parametrize("path", _catalogs(), ids=lambda p: p.stem)
def test_no_translation_is_another_english_key(path):
    """The page translates text as it appears, including the text it just wrote, so a
    translation that is itself a key with a different translation would flip back and
    forth."""
    msgs = json.loads(path.read_text(encoding="utf-8"))["messages"]
    norm = {" ".join(k.split()): v for k, v in msgs.items()}
    flips = [(k, v) for k, v in msgs.items()
             if " ".join(v.split()) in norm and norm[" ".join(v.split())] != v]
    assert not flips


def test_the_language_is_the_choice_then_the_system_then_english():
    assert i18n.resolve("es", ["en-US"]) == "es"
    assert i18n.resolve("en", ["es-AR", "es"]) == "en"
    assert i18n.resolve(None, ["es-419", "en"]) == "es"
    assert i18n.resolve(None, ["es_MX"]) == "es"
    assert i18n.resolve(None, ["fr-FR", "de"]) == "en"
    assert i18n.resolve("xx", []) == "en"


def test_the_page_gets_the_language_its_browser_asks_for():
    cl = _client()
    es = _served(cl, **{"Accept-Language": "es-AR,es;q=0.9,en;q=0.5"})
    assert es["lang"] == "es" and es["setting"] == "auto"
    assert es["messages"]["Recent cases"] == "Casos recientes"
    assert es["languages"] == {"en": "English", "es": "Español"}
    en = _served(cl, **{"Accept-Language": "en-US,en;q=0.9"})
    assert en["lang"] == "en" and en["messages"] == {}
    assert en["help"] == "/static/help.html"


def test_the_examiners_choice_is_kept_app_wide_and_wins():
    cl = _client()
    assert cl.post("/api/settings", json={"language": "es"}).get_json() == {
        "ok": True, "language": "es"}
    assert appconfig.get_language() == "es"
    got = _served(cl, **{"Accept-Language": "en-US"})
    assert got["lang"] == "es" and got["setting"] == "es"

    assert cl.post("/api/settings", json={"language": "auto"}).status_code == 200
    assert appconfig.get_language() is None
    assert _served(cl, **{"Accept-Language": "en-US"})["lang"] == "en"

    assert cl.post("/api/settings", json={"language": "xx"}).status_code == 400
    assert appconfig.get_language() is None


def test_the_manual_follows_the_language_when_it_is_translated():
    assert i18n.help_page("en") == "/static/help.html"
    want = "/static/help.es.html" if (STATIC / "help.es.html").is_file() else "/static/help.html"
    assert i18n.help_page("es") == want


def test_the_catalog_is_loaded_before_the_page_and_app_js():
    page = TEMPLATE.read_text(encoding="utf-8")
    config, script, app = (page.index('<script src="/i18n.js">'),
                           page.index('<script src="/static/i18n.js">'),
                           page.index('<script src="/static/app.js">'))
    assert config < script < page.index("<body>") < app


def test_evidence_is_held_back_from_translation():
    """translate="no" is what keeps the page's translation (and a browser's) off file
    names, paths, metadata, category and flag names and the manual."""
    page = TEMPLATE.read_text(encoding="utf-8")
    assert '<div id="helpDoc" translate="no">' in page
    assert '<h1 id="caseName" translate="no">' in page
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    for held in ('<div class="fname" translate="no">',            # a tile's file name
                 '<tbody translate="no">',                         # the list's rows
                 '<h2 translate="no">',                            # the details pane's name
                 '<div class="path" translate="no">',              # ... and path
                 '<span class="catnow" translate="no"',            # ... and category
                 '<span class="flagchip" translate="no">',         # ... and flags
                 '<td class="mono" translate="no">',               # ... and hashes
                 '<option translate="no">'):                       # the Source filter
        assert held in js, held
