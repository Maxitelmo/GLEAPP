#!/usr/bin/env python3
"""Say how a translation of the gallery stands against the English it translates.

A catalog (gleapp/web/static/i18n/<lang>.json) is keyed by the English the page shows,
so it drifts when the English does, and silently: a key whose English was reworded
matches nothing and the page shows the new English, which is safe but untranslated.
This lists the two things a translator needs:

  stale      keys holding a word that is no longer anywhere in the sources (reword or drop)
  missing    strings of the page's markup that no key covers (translate)

    python3 tools/i18n_report.py es
    python3 tools/i18n_report.py es --stale-only

It is a report, not a check the suite runs: an English change by someone who does not
write the other language must not fail CI. Stale is decided word by word, not by the
whole string, because many keys are the text app.js assembles at run time from parts
("1 other member image was found", from "image" + " was"), which no source holds
verbatim; so a reword that only reorders words is not caught. Strings app.js builds
are not listed as missing either, since their final text exists only in a browser.
Exit status is 1 when anything is stale.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "gleapp"
PAGE = PKG / "web" / "templates" / "index.html"
SCRIPTS = [PKG / "web" / "static" / "app.js", PKG / "web" / "static" / "i18n.js"]
KEY_PH = re.compile(r"\{([a-z][a-z0-9_]*)(:t)?\}")
ATTRS = ("title", "placeholder", "alt", "aria-label", "label")


def _norm(s: str) -> str:
    return " ".join(s.split())


def _js_text(src: str) -> str:
    """The script's text with its escapes decoded and adjacent literals joined, so a
    message written as "a " + "b" or `a` + `b` reads as it is shown."""
    src = re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), src)
    src = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), src)
    src = src.replace('\\"', '"').replace("\\'", "'").replace("\\n", " ")
    src = re.sub(r"[\"'`]\s*\+\s*[\"'`]", "", src)
    return src


def sources() -> str:
    parts = [html.unescape(PAGE.read_text(encoding="utf-8"))]
    parts += [html.unescape(_js_text(p.read_text(encoding="utf-8"))) for p in SCRIPTS]
    parts += [p.read_text(encoding="utf-8") for p in sorted(PKG.rglob("*.py"))
              if "vendor" not in p.parts]
    return _norm("\n".join(parts))


WORD = re.compile(r"[A-Za-z][A-Za-z'-]+")


def stale(messages: dict, text: str) -> list[str]:
    known = set(WORD.findall(text))
    out = []
    for key in messages:
        k = key.split("|", 1)[1] if re.match(r"^[a-z]+\|", key) else key
        fixed = " ".join(KEY_PH.split(k)[::3])
        if any(w not in known for w in WORD.findall(fixed)):
            out.append(key)
    return out


class _PageText(HTMLParser):
    """The text and tooltip strings of the page's markup, outside script, style, code
    and anything marked translate="no"."""

    VOID = {"br", "img", "input", "meta", "link", "col", "hr", "source", "path"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.held, self.found = [], 0, []

    def _add(self, s):
        s = _norm(s)
        if re.search(r"[A-Za-z]{2}", s) and s not in self.found:
            self.found.append(s)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        held = a.get("translate") == "no"
        if tag not in self.VOID:
            self.stack.append((tag, held))
        self.held += held
        if not self.held:
            for k in ATTRS:
                if a.get(k):
                    self._add(a[k])
        if held and tag in self.VOID:
            self.held -= 1

    def handle_endtag(self, tag):
        while self.stack:
            t, held = self.stack.pop()
            self.held -= held
            if t == tag:
                break

    def handle_data(self, data):
        if not self.held and not any(t in ("script", "style", "code", "pre", "kbd")
                                     for t, _ in self.stack):
            self._add(data)


def missing(messages: dict) -> list[str]:
    keys = {_norm(k) for k in messages}
    patterns = [re.compile("^" + "".join(
        "(.*?)" if i % 3 == 1 else re.escape(p) for i, p in enumerate(KEY_PH.split(k))
        if i % 3 != 2) + "$") for k in keys if KEY_PH.search(k)]
    parser = _PageText()
    parser.feed(PAGE.read_text(encoding="utf-8"))
    return [s for s in parser.found
            if s not in keys and not any(p.match(s) for p in patterns)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("lang", help="the catalog's language code, e.g. es")
    ap.add_argument("--stale-only", action="store_true")
    args = ap.parse_args(argv)
    path = PKG / "web" / "static" / "i18n" / f"{args.lang}.json"
    messages = json.loads(path.read_text(encoding="utf-8"))["messages"]
    old = stale(messages, sources())
    print(f"{path.relative_to(REPO)}: {len(messages)} messages, {len(old)} stale")
    for k in old:
        print(f"  stale    {k!r}")
    if not args.stale_only:
        gone = missing(messages)
        print(f"page strings no key covers: {len(gone)}")
        for s in gone:
            print(f"  missing  {s!r}")
    return 1 if old else 0


if __name__ == "__main__":
    sys.exit(main())
