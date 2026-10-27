"""The interface language of the review gallery.

The gallery is written in English, and a translation is a catalog: a JSON file in
``web/static/i18n/`` mapping each English string, as the page shows it, to the same
string in another language. ``web/static/i18n.js`` applies it in the page, so the
English source stays the only source and a string the catalog lacks is shown in
English rather than lost.

What is translated is the interface: labels, buttons, tooltips, messages and the
manual. Evidence is not: a file's name, path and metadata, the categories and flags
the examiner named, and every report, CSV and JSON export, whose column names other
tools read, stay as they are whatever language the window is in.

The language is the examiner's choice, kept app-wide in ``config.json``
(``appconfig.get_language``); with no choice made, the one the system asks for
(the browser's or web view's Accept-Language) if a catalog exists for it, else
English.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable

DEFAULT = "en"
STATIC = Path(__file__).parent / "web" / "static"
CATALOGS = STATIC / "i18n"

# A placeholder in a catalog key, ``{name}`` or ``{name:t}``; the second asks the page
# to translate what it stands for too. In a translation, ``{name}`` or
# ``{name?if set|if empty}``.
KEY_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)(:t)?\}")
OUT_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)(\?[^{}]*)?\}")
# a placeholder that holds an English plural ending ("s", "es", or nothing), which a
# translation may leave out
PLURAL_ENDINGS = frozenset({"s", "es"})


@lru_cache(maxsize=None)
def _catalog(code: str) -> dict:
    try:
        data = json.loads((CATALOGS / f"{code}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def languages() -> dict[str, str]:
    """``{code: name}`` of every language the gallery can be shown in, English
    first, each named in its own language."""
    out = {DEFAULT: "English"}
    for p in sorted(CATALOGS.glob("*.json")):
        cat = _catalog(p.stem)
        if cat.get("messages"):
            out[p.stem] = str(cat.get("name") or p.stem)
    return out


def resolve(setting: str | None, accepted: Iterable[str] = ()) -> str:
    """The language to show: the examiner's ``setting`` when it names one there is,
    else the first of ``accepted`` (language tags in preference order, ``es-419``
    or ``es``) there is a catalog for, else English."""
    known = languages()
    if setting in known:
        return setting
    for tag in accepted:
        base = str(tag).split("-")[0].split("_")[0].strip().lower()
        if base in known:
            return base
    return DEFAULT


def messages(code: str) -> dict[str, str]:
    """The catalog's translations, English string to translated string; empty for
    English."""
    if code == DEFAULT:
        return {}
    msgs = _catalog(code).get("messages")
    return dict(msgs) if isinstance(msgs, dict) else {}


def help_page(code: str) -> str:
    """The URL of the manual in that language, or of the English one when there is
    no translation of it."""
    if code != DEFAULT and (STATIC / f"help.{code}.html").is_file():
        return f"/static/help.{code}.html"
    return "/static/help.html"


def client_config(code: str, setting: str | None) -> dict:
    """What the page needs before it draws anything: the language, what the examiner
    chose (``auto`` for none), the choices, the catalog and the manual's URL."""
    return {"lang": code, "setting": setting or "auto", "languages": languages(),
            "messages": messages(code), "help": help_page(code)}
