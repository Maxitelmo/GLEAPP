"""Content Credentials (C2PA) and IPTC digital source type, recorded as provenance.

This module records what a file's own provenance metadata declares, who signed it, and
whether the signature validates. It is not a classifier: it never says whether content
is synthetic, gives no score, and nothing in GLEAPP sets or changes a category from it.

    state        absent | malformed | invalid | valid_untrusted | trusted | not_checked
    active_dst   the digital source type the active manifest's actions declare, as a URI
    dst_class    the vocabulary group that URI belongs to (``DST_CLASSES``)
    xmp_dst      an IPTC DigitalSourceType found in XMP, an *unsigned declaration*, kept
                 apart from the C2PA state and never folded into it

The state follows the validator in c2pa-python (c2pa-rs 0.91.0), not the raw failure
list. C2PA 2.2 puts ``signingCredential.untrusted`` in its failure table (§15.2.2.3) yet
makes it block only *Trusted* (§14.3.5, §14.3.6), and c2pa-rs reports such a manifest
``Valid``; GLEAPP records it ``valid_untrusted``. ``malformed`` is split out of an
``Invalid`` result by the C2PA Asset Rubrics v1.0 well-formed codes, and also covers a
manifest store the reader could not parse at all.

Reading is offline. The reader is opened with remote manifest and OCSP fetching off, no
network host allowed and CAWG identity assertions left undecoded (their did:web issuers
are fetched otherwise). A manifest kept only at a remote address is therefore
``not_checked``, with the address recorded: fetching it would tell a third party which
evidence is being examined.

c2pa-python is an optional extra (``pip install -e ".[provenance]"``). Without it every
file is ``not_checked`` with ``NOT_CHECKED_LIBRARY``, never an empty value that could
pass for "no credentials". It also looks for its native library in the working
directory before its own package folder, so it is not imported while one sits there.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, BinaryIO, Iterable

STATES = ("absent", "malformed", "invalid", "valid_untrusted", "trusted", "not_checked")
# "Trusted" on its own reads as content worth trusting, so neither valid state is
# called that: each says whether the signer is on a trust list GLEAPP holds. The
# stored values (``STATES``) are unchanged.
STATE_LABELS = {
    "absent": "No Content Credentials",
    "malformed": "Malformed",
    "invalid": "Invalid",
    "valid_untrusted": "Valid, signer not on a trust list",
    "trusted": "Valid, signer on a trust list",
    "not_checked": "Not checked",
}
# The same states, short enough for a list column (16 characters at most).
STATE_SHORT = {
    "absent": "None",
    "malformed": "Malformed",
    "invalid": "Invalid",
    "valid_untrusted": "Valid, unlisted",
    "trusted": "Valid, listed",
    "not_checked": "Not checked",
}
DST_CLASSES = ("generative_ai", "ai_composite", "algorithmic", "algorithmically_altered",
               "capture", "composite_capture", "composite", "screen", "virtual_recording",
               "human_edit", "other", "none")
# What each class of a declared digital source type is called on a screen or in a
# report. They name the vocabulary group of what the file declares, nothing more.
DST_CLASS_LABELS = {
    "generative_ai": "Generative AI",
    "ai_composite": "Composite with AI",
    "algorithmic": "Algorithmic",
    "algorithmically_altered": "Algorithmically-altered media",
    "capture": "Capture",
    "composite_capture": "Composite of captured elements",
    "composite": "Composite of elements",
    "screen": "Screen capture",
    "virtual_recording": "Virtual event recording",
    "human_edit": "Human edits",
    "other": "Other",
    "none": "None declared",
}
UNSIGNED = "unsigned declaration"
NOT_CHECKED_LIBRARY = "C2PA not checked: library unavailable"
REMOTE_NOT_FETCHED = "remote manifest not fetched (offline)"
PLANTED = "C2PA not checked: a c2pa library sits in the working directory"

# Fixed wording for the report and the manual; see "What a state does not mean" there.
CAVEAT = (
    "Content Credentials record what the signer declared. A valid signature shows the "
    "credentials were not changed after signing; who signed is established only when "
    "the signer's certificate is on a trust list GLEAPP holds (trusted). An AI source "
    "type is a declaration, not a finding. Absence of credentials does not indicate "
    "authenticity: many platforms and tools remove them."
)

# The digital source type vocabulary, grouped. IPTC's terms live under
# http://cv.iptc.org/newscodes/digitalsourcetype/ and C2PA adds two of its own under
# http://c2pa.org/digitalsourcetype/ (C2PA 2.2 §18.14.4.5). A URI is matched on its
# exact last segment, so compositeWithTrainedAlgorithmicMedia is never read as
# trainedAlgorithmicMedia, and a term in no known namespace is "other".
#
# A class whose label names AI holds only terms whose IPTC definition includes
# generative AI (IPTC's release of 2024-10-23, which tests/test_provenance_iptc.py
# holds these labels and groups to). virtualRecording is "Virtual event
# recording", a live recording of a virtual event "based on Generative AI and/or
# captured elements": it can hold no AI at all, so it is a class of its own.
# compositeSynthetic, "Composite including generative AI elements", has at least one.
#
# "Human edits" holds only humanEdits and minorHumanEdits. Each term that is not a
# human's edit has a class of its own under IPTC's label: "Composite of elements",
# whose elements may or may not be generative AI, so calling it an edit would deny
# what the term leaves open; "Composite of captured elements", every element captured
# from real life; and "Algorithmically-altered media" (algorithmicallyEnhanced), an
# algorithm's change, initiated or configured by a human, that leaves the main content
# as it was, such as sharpening or noise reduction.
_DST_GROUPS = {
    "generative_ai": ("trainedAlgorithmicMedia", "trainedAlgorithmicData"),
    "ai_composite": ("compositeWithTrainedAlgorithmicMedia", "compositeSynthetic"),
    "algorithmic": ("algorithmicMedia",),
    "algorithmically_altered": ("algorithmicallyEnhanced",),
    "capture": ("digitalCapture", "computationalCapture", "negativeFilm", "positiveFilm",
                "print"),
    "composite_capture": ("compositeCapture",),
    "composite": ("composite",),
    "screen": ("screenCapture",),
    "virtual_recording": ("virtualRecording",),
    "human_edit": ("humanEdits", "minorHumanEdits"),
}
_DST_TERM_CLASS = {term: cls for cls, terms in _DST_GROUPS.items() for term in terms}
# The classes whose label names AI, and their terms: what the gallery's "AI declared"
# mark looks for (``ai_declaration``).
AI_CLASSES = frozenset(("generative_ai", "ai_composite"))
AI_TERMS = tuple(term for cls in sorted(AI_CLASSES) for term in _DST_GROUPS[cls])
_IPTC_NAMESPACE = "cv.iptc.org/newscodes/digitalsourcetype/"
_DST_NAMESPACES = (_IPTC_NAMESPACE, "c2pa.org/digitalsourcetype/")
# The terms IPTC has retired (release of 2024-10-23). A file can still declare
# one, so each is read and keeps its class; wherever a term is shown, it says so.
RETIRED_TERMS = frozenset(("minorHumanEdits", "digitalArt", "softwareImage"))
# What a file declares is the URI, and every record keeps it; the class is worked out
# from it. ``load`` works each class out again, and a case's c2pa_dst_class column is
# worked out again once per value of this (``CaseDB.refresh_dst_classes``), so **a
# build that moves a term to another class has to raise it**, or every case an older
# build read keeps the older class in the column the filter and the list read.
DST_VOCABULARY = 3       # 2: virtualRecording left "Composite with AI"
                         # 3: composite, compositeCapture, algorithmicallyEnhanced
                         #    left "Human edits"

# The codes C2PA's Asset Rubrics v1.0 (C2PA Conformance Task Force, 2026-08-06,
# conformance-public asset-rubrics/asset-rubric-integrity.yml, CC BY 4.0) treat as
# "not well-formed". An Invalid manifest that carries one is recorded as malformed.
WELL_FORMED_CODES = frozenset((
    "assertion.action.malformed", "assertion.bmffHash.malformed",
    "assertion.boxesHash.malformed", "assertion.collectionHash.malformed",
    "assertion.dataHash.malformed", "assertion.external-reference.malformed",
    "assertion.external-reference.labelMismatch", "assertion.external-reference.created",
    "assertion.ingredient.malformed", "assertion.alternativeContentRepresentation.malformed",
    "assertion.alternativeContentRepresentation.missing", "assertion.multiAssetHash.malformed",
    "assertion.cbor.invalid", "assertion.json.invalid", "claim.cbor.invalid",
    "claim.hardBindings.missing", "claim.malformed", "claim.missing", "claim.multiple",
    "hashedURI.missing", "ingredient.manifest.missing", "assertion.boxesHash.unknownBox",
    "assertion.multipleHardBindings", "manifest.compressed.invalid",
    "manifest.html.multipleManifests", "manifest.inaccessible", "manifest.multipleParents",
    "manifest.structuredText.emptyReference", "manifest.structuredText.malformedReference",
    "manifest.structuredText.multipleReferences", "manifest.structuredText.noManifest",
    "manifest.structuredText.noResolutionPath", "manifest.timestamp.invalid",
    "manifest.timestamp.wrongParents", "manifest.update.invalid",
    "manifest.update.wrongParents",
))
# The hard bindings tie a manifest to the content it was signed for. A mismatch says
# the content is not that content, not why: content changed after signing fails the
# same way as a manifest carried over from other content.
HARD_BINDING_MISMATCH = frozenset((
    "assertion.dataHash.mismatch", "assertion.bmffHash.mismatch",
    "assertion.boxesHash.mismatch", "assertion.collectionHash.mismatch",
))
# Failures c2pa-rs tolerates in a Valid manifest: an untrusted signer, and CAWG
# identity results, which say nothing about the claim signature.
_TOLERATED_PREFIXES = ("cawg.x509.", "cawg.identity.")
_TOLERATED = frozenset(("signingCredential.untrusted",))
MAX_DEPTH = 8          # how deep ingredient manifests are followed
MAX_ACTIONS = 64       # most declared actions kept per manifest; the rest are counted
_MAX_TEXT = 300        # longest explanation or message kept per code

_MAX_BLOCK = 32 * 1024 * 1024
_XMP_SIG = b"http://ns.adobe.com/xap/1.0/\x00"
_XMP_EXT_SIG = b"http://ns.adobe.com/xmp/extension/\x00"
_UUID_C2PA = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
_UUID_XMP = bytes.fromhex("be7acfcb97a942e89c71999491e3afac")
_HEIF_BRANDS = {b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1",
                b"msf1", b"avif", b"avis", b"mif2"}


def classify_dst(uri: str | None) -> str:
    """The group of ``DST_CLASSES`` a digital source type URI belongs to."""
    if not uri:
        return "none"
    text = str(uri).strip()
    low = text.lower()
    if low.startswith("c2pa."):          # the deprecated c2pa.trainedAlgorithmicData label
        term = text[5:]
    elif any(ns in low for ns in _DST_NAMESPACES):
        term = text.rstrip("/").rsplit("/", 1)[-1]
    else:
        return "other"
    return _DST_TERM_CLASS.get(term, "other")


# -- the manifest store, parsed (no I/O) ------------------------------------------------

def _codes(block: Any) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"success": [], "informational": [], "failure": []}
    if not isinstance(block, dict):
        return out
    for kind in out:
        for item in block.get(kind) or []:
            if isinstance(item, dict) and item.get("code"):
                entry = {"code": str(item["code"])}
                if item.get("explanation"):
                    entry["explanation"] = str(item["explanation"])[:_MAX_TEXT]
                out[kind].append(entry)
    return out


def _codes_from_status(status: Any) -> dict[str, list[dict]]:
    """``validation_status`` (a flat list) when ``validation_results`` is missing:
    every entry there is a problem, so each one is a failure."""
    out: dict[str, list[dict]] = {"success": [], "informational": [], "failure": []}
    for item in status or []:
        if isinstance(item, dict) and item.get("code"):
            out["failure"].append({"code": str(item["code"]),
                                   "explanation": str(item.get("explanation") or "")[:_MAX_TEXT]})
    return out


def _blocking(failures: list[str]) -> list[str]:
    return [c for c in failures
            if c not in _TOLERATED and not c.startswith(_TOLERATED_PREFIXES)]


def _state(validation_state: Any, success: list[str], failures: list[str],
           trust_list_uri: str | None, tsa_uris: frozenset) -> tuple[str, str | None]:
    """(state, reason). ``failures`` is the current validation only: the active
    manifest's and the ingredient deltas', never what an ingredient recorded when it
    was signed."""
    vs = str(validation_state).lower() if validation_state else None
    blocking = _blocking(failures)
    if vs is None:                        # not reported: decide the way c2pa-rs does
        if blocking:
            vs = "invalid"
        elif "signingCredential.trusted" in success:
            vs = "trusted"
        else:
            vs = "valid"
    if vs == "invalid":
        if any(c in WELL_FORMED_CODES for c in failures):
            return "malformed", None
        return "invalid", None
    if vs == "trusted":
        # c2pa-rs 0.91.0 also trusts a signer that chains to an anchor loaded as a
        # time-stamping authority; the TSA list does not vouch for signers.
        if trust_list_uri and trust_list_uri in tsa_uris:
            return "valid_untrusted", ("signer chains only to the TSA trust list, "
                                       "which does not vouch for signers")
        return "trusted", None
    return "valid_untrusted", None


def _signer(manifest: dict) -> dict | None:
    sig = manifest.get("signature_info") or {}
    if not isinstance(sig, dict) or not (sig.get("issuer") or sig.get("common_name")):
        return None
    return {k: str(sig[k]) for k in ("issuer", "common_name", "cert_serial_number")
            if sig.get(k)}


def signer_text(signer: dict | None) -> str:
    """'common name (issuer)' for a signer as ``parse_manifest_store`` records it."""
    if not signer:
        return ""
    cn, org = signer.get("common_name"), signer.get("issuer")
    if cn and org and cn != org:
        return f"{cn} ({org})"
    return cn or org or ""


def _claim_generator(manifest: dict) -> str | None:
    if manifest.get("claim_generator"):
        return str(manifest["claim_generator"])
    parts = []
    for info in manifest.get("claim_generator_info") or []:
        if isinstance(info, dict) and info.get("name"):
            parts.append(" ".join(str(info[k]) for k in ("name", "version") if info.get(k)))
    return "; ".join(parts) or None


def _dst(manifest: dict) -> tuple[str | None, str | None]:
    """(digital source type URI, the action that declares it). The c2pa.created
    action's comes first (C2PA 2.2 §18.14.2), then the first action that has one."""
    found: list[tuple[str, str]] = []
    for assertion in manifest.get("assertions") or []:
        if not isinstance(assertion, dict):
            continue
        if not str(assertion.get("label") or "").startswith("c2pa.actions"):
            continue
        for act in (assertion.get("data") or {}).get("actions") or []:
            if isinstance(act, dict) and act.get("digitalSourceType"):
                found.append((str(act["digitalSourceType"]), str(act.get("action") or "")))
    for uri, action in found:
        if action == "c2pa.created":
            return uri, action
    return found[0] if found else (None, None)


def _agent(agent: Any) -> str | None:
    """A softwareAgent as declared: its name and version, or the string an actions
    v1 assertion carries."""
    if isinstance(agent, dict):
        return " ".join(str(agent[k]) for k in ("name", "version") if agent.get(k)) or None
    return str(agent) if agent not in (None, "") else None


def _actions(manifest: dict) -> tuple[list[dict], int]:
    """(each action the manifest's actions assertions declare, in order, with the
    softwareAgent it names; how many past ``MAX_ACTIONS`` were left out). Written
    down as declared, never classified. c2pa-rs 0.91.0 returns a softwareAgent as a
    name and version, as a string, or as softwareAgentIndex into the assertion's
    softwareAgents (C2PA 2.2 §18.14)."""
    out: list[dict] = []
    total = 0
    for assertion in manifest.get("assertions") or []:
        if not isinstance(assertion, dict) or \
                not str(assertion.get("label") or "").startswith("c2pa.actions"):
            continue
        data = assertion.get("data")
        if not isinstance(data, dict):
            continue
        agents = data.get("softwareAgents")
        agents = agents if isinstance(agents, list) else []
        for act in data.get("actions") or []:
            if not isinstance(act, dict):
                continue
            total += 1
            if len(out) >= MAX_ACTIONS:
                continue
            entry = {"action": str(act.get("action") or "")[:_MAX_TEXT]}
            agent = _agent(act.get("softwareAgent"))
            index = act.get("softwareAgentIndex")
            if agent is None and index is not None:
                listed = isinstance(index, int) and not isinstance(index, bool)
                if listed and 0 <= index < len(agents):
                    agent = _agent(agents[index])
                else:
                    agent = (f"softwareAgentIndex {index}, not in the assertion's "
                             "softwareAgents")
            if agent:
                entry["software_agent"] = agent[:_MAX_TEXT]
            out.append(entry)
    return out, total - len(out)


def _delta_failures(results: dict, manifest_label: str | None, ingredient: dict) -> list[str]:
    """Current failures for one ingredient, from the parent's ingredientDeltas."""
    out = []
    label = ingredient.get("label")
    for delta in (results or {}).get("ingredientDeltas") or []:
        uri = str(delta.get("ingredientAssertionURI") or "")
        if label and uri.endswith("/c2pa.assertions/" + str(label)) and \
                (not manifest_label or f"/{manifest_label}/" in uri):
            out += [c["code"] for c in _codes(delta.get("validationDeltas"))["failure"]]
    return out


def _ingredients(store: dict, manifest: dict, results: dict, tsa_uris: frozenset,
                 depth: int, seen: set) -> list[dict]:
    out = []
    for ing in manifest.get("ingredients") or []:
        if not isinstance(ing, dict):
            continue
        entry: dict[str, Any] = {"title": ing.get("title"), "relationship": ing.get("relationship")}
        label = ing.get("active_manifest")
        child = (store.get("manifests") or {}).get(label) if label else None
        if not isinstance(child, dict):
            entry.update(dst=None, dst_class="none", state="absent", signer=None)
            out.append(entry)
            continue
        recorded = _codes((ing.get("validation_results") or {}).get("activeManifest"))
        failures = [c["code"] for c in recorded["failure"]]
        failures += _delta_failures(results, manifest.get("label"), ing)
        success = [c["code"] for c in recorded["success"]]
        state, reason = _state(None, success, failures, None, tsa_uris)
        dst, _action = _dst(child)
        entry.update(dst=dst, dst_class=classify_dst(dst), state=state,
                     signer=_signer(child))
        if reason:
            entry["state_reason"] = reason
        if depth < MAX_DEPTH and label not in seen:
            nested = _ingredients(store, child, {}, tsa_uris, depth + 1, seen | {label})
            if nested:
                entry["ingredients"] = nested
        elif label in seen or depth >= MAX_DEPTH:
            entry["ingredients_not_followed"] = ("cycle" if label in seen
                                                 else f"deeper than {MAX_DEPTH}")
        out.append(entry)
    return out


def parse_manifest_store(store: dict, *, tsa_uris: Iterable[str] = ()) -> dict:
    """The provenance record of a manifest store, as c2pa-python's ``Reader.json()``
    returns it. Pure: no file, no library. ``tsa_uris`` are the trust_uri values the
    time-stamping anchors were loaded under, so a Trusted result that rests on one of
    them can be told apart."""
    tsa_uris = frozenset(tsa_uris)
    manifests = store.get("manifests") or {}
    label = store.get("active_manifest")
    manifest = manifests.get(label) if label else None
    results = store.get("validation_results") or {}
    if not isinstance(manifest, dict):
        return {"state": "malformed", "state_reason": "no active manifest in the store",
                "codes": _codes(None), "ingredients": []}
    active = results.get("activeManifest")
    codes = _codes(active) if active is not None else _codes_from_status(
        store.get("validation_status"))
    failures = [c["code"] for c in codes["failure"]]
    for delta in results.get("ingredientDeltas") or []:
        failures += [c["code"] for c in _codes(delta.get("validationDeltas"))["failure"]]
    success = [c["code"] for c in codes["success"]]
    trust_list_uri = results.get("trustListUri")
    state, reason = _state(store.get("validation_state"), success, failures,
                           trust_list_uri, tsa_uris)
    dst, action = _dst(manifest)
    record: dict[str, Any] = {
        "state": state,
        "codes": codes,
        "signer": _signer(manifest),
        "claim_generator": _claim_generator(manifest),
        "signed_time": (manifest.get("signature_info") or {}).get("time"),
        "active_manifest": label,
        "active_dst": dst,
        "dst_class": classify_dst(dst),
        "dst_action": action,
        # C2PA 2.2 §15.3: data from a manifest that is not valid is not attributable
        # to its signer; it is recorded, and marked so
        "dst_signed_valid": bool(dst) and state in ("valid_untrusted", "trusted"),
        "hard_binding_mismatch": any(c in HARD_BINDING_MISMATCH for c in failures),
        "ingredients": _ingredients(store, manifest, results, tsa_uris, 1, {label}),
        "spec_version": results.get("specVersion"),
        "trust_list_uri": trust_list_uri,
        "timestamp_trust_list_uri": results.get("timestampTrustListUri"),
    }
    record["actions"], omitted = _actions(manifest)
    if omitted:
        record["actions_omitted"] = omitted
    if reason:
        record["state_reason"] = reason
    return record


# -- the bytes: where a manifest store and XMP sit ------------------------------------

class _Blocks:
    def __init__(self) -> None:
        self.mime: str = ""
        self.known: bool = False          # a container this module walks fully
        self.xmp: list[bytes] = []
        self.stores: list[str] = []       # where a C2PA manifest store was seen


def _read(fh: BinaryIO, n: int) -> bytes:
    """``n`` bytes, or none past the cap; the position moves past them either way.
    A block that ends early raises ValueError: the file stops inside a block the
    scan reads, so what was cut off cannot be called absent from the bytes."""
    if n < 0:
        return b""
    if n > _MAX_BLOCK:
        fh.seek(n, 1)
        return b""
    data = fh.read(n)
    if len(data) < n:
        raise ValueError("block cut short")
    return data


def _jpeg(fh: BinaryIO, out: _Blocks) -> None:
    out.mime = "image/jpeg"
    fh.seek(2)
    ext: dict[bytes, bytes] = {}
    while True:
        if fh.read(1) != b"\xff":
            break
        b = fh.read(1)
        while b == b"\xff":
            b = fh.read(1)
        if not b:
            break
        marker = b[0]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker in (0xDA, 0xD9):          # start of scan, end of image
            break
        raw = fh.read(2)
        if len(raw) < 2:
            break
        length = struct.unpack(">H", raw)[0] - 2
        if length < 0:
            break
        if marker == 0xE1:
            data = _read(fh, length)
            if data.startswith(_XMP_SIG):
                out.xmp.append(data[len(_XMP_SIG):])
            elif data.startswith(_XMP_EXT_SIG) and len(data) > len(_XMP_EXT_SIG) + 40:
                body = data[len(_XMP_EXT_SIG):]
                ext[body[:32]] = ext.get(body[:32], b"") + body[40:]
        elif marker == 0xEB:                # APP11: JPEG XT boxes, a JUMBF store
            data = _read(fh, length)
            if data[:2] == b"JP" and b"c2pa" in data and "JPEG APP11" not in out.stores:
                out.stores.append("JPEG APP11")
        else:
            fh.seek(length, 1)
    out.xmp.extend(ext.values())
    out.known = True


def _png(fh: BinaryIO, out: _Blocks) -> None:
    import zlib  # pylint: disable=import-outside-toplevel
    out.mime = "image/png"
    fh.seek(8)
    while True:
        head = fh.read(8)
        if len(head) < 8:
            break
        length, ctype = struct.unpack(">I", head[:4])[0], head[4:]
        if ctype == b"iTXt":
            data = _read(fh, length)
            fh.seek(4, 1)
            key, _, rest = data.partition(b"\x00")
            if key == b"XML:com.adobe.xmp" and len(rest) > 2:
                flag, rest = rest[0], rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _tkey, _, text = rest.partition(b"\x00")
                try:
                    out.xmp.append(zlib.decompress(text) if flag else text)
                except zlib.error:
                    pass
        elif ctype == b"caBX":
            fh.seek(length + 4, 1)
            out.stores.append("PNG caBX")
        elif ctype == b"IEND":
            break
        else:
            fh.seek(length + 4, 1)
    out.known = True


def _webp(fh: BinaryIO, out: _Blocks) -> None:
    out.mime = "image/webp"
    fh.seek(12)
    while True:
        head = fh.read(8)
        if len(head) < 8:
            break
        ctype, length = head[:4], struct.unpack("<I", head[4:])[0]
        pad = length & 1
        if ctype == b"XMP ":
            out.xmp.append(_read(fh, length))
            fh.seek(pad, 1)
        else:
            if ctype == b"C2PA":
                out.stores.append("WebP C2PA")
            fh.seek(length + pad, 1)
    out.known = True


def _tiff(fh: BinaryIO, out: _Blocks) -> None:
    out.mime = "image/tiff"
    fh.seek(0)
    head = fh.read(8)
    end = "<" if head[:2] == b"II" else ">"
    fh.seek(struct.unpack(end + "I", head[4:8])[0])
    raw = fh.read(2)
    if len(raw) < 2:
        return
    for _ in range(min(struct.unpack(end + "H", raw)[0], 4096)):
        entry = fh.read(12)
        if len(entry) < 12:
            break
        tag, typ, count = struct.unpack(end + "HHI", entry[:8])
        if tag == 52545:
            out.stores.append("TIFF tag 52545")
        elif tag == 700 and typ in (1, 2, 7):
            here = fh.tell()
            if count <= 4:
                out.xmp.append(entry[8:8 + count])
            else:
                fh.seek(struct.unpack(end + "I", entry[8:12])[0])
                out.xmp.append(_read(fh, count))
                fh.seek(here)
    out.known = True


def _boxes(fh: BinaryIO, start: int, end: int):
    """(type, payload offset, payload size) of each ISOBMFF box in [start, end)."""
    pos = start
    while pos + 8 <= end:
        fh.seek(pos)
        head = fh.read(8)
        if len(head) < 8:
            return
        size, btype = struct.unpack(">I", head[:4])[0], head[4:]
        hdr = 8
        if size == 1:
            big = fh.read(8)
            if len(big) < 8:
                return
            size, hdr = struct.unpack(">Q", big)[0], 16
        elif size == 0:
            size = end - pos
        if size < hdr:
            return
        yield btype, pos + hdr, size - hdr
        pos += size


def _uint(data: bytes, pos: int, n: int) -> int:
    return int.from_bytes(data[pos:pos + n], "big") if n else 0


def _heif_xmp(fh: BinaryIO, meta: bytes, out: _Blocks) -> None:
    """The XMP item of a HEIF ``meta`` box (an infe of type 'mime' with content type
    application/rdf+xml), located through iloc."""
    want: set[int] = set()
    iloc = idat = None
    pos = 4
    while pos + 8 <= len(meta):
        size, btype = struct.unpack(">I", meta[pos:pos + 4])[0], meta[pos + 4:pos + 8]
        if size < 8:
            break
        body = meta[pos + 8:pos + size]
        if btype == b"iinf":
            p = 4 + (2 if body[0] == 0 else 4)
            while p + 8 <= len(body):
                isz, it = struct.unpack(">I", body[p:p + 4])[0], body[p + 4:p + 8]
                if isz < 8:
                    break
                infe = body[p + 8:p + isz]
                if it == b"infe" and infe and infe[0] >= 2:
                    idn = 2 if infe[0] == 2 else 4
                    item_id = _uint(infe, 4, idn)
                    q = 4 + idn + 2
                    rest = infe[q + 4:].split(b"\x00")
                    if infe[q:q + 4] == b"mime" and len(rest) > 1 and \
                            rest[1].strip().lower() == b"application/rdf+xml":
                        want.add(item_id)
                p += isz
        elif btype == b"iloc":
            iloc = body
        elif btype == b"idat":
            idat = body
        pos += size
    if not want or iloc is None:
        return
    ver = iloc[0]
    off_sz, len_sz = iloc[4] >> 4, iloc[4] & 15
    base_sz, idx_sz = iloc[5] >> 4, (iloc[5] & 15) if ver in (1, 2) else 0
    idn = 2 if ver < 2 else 4
    p = 6
    count = _uint(iloc, p, idn)
    p += idn
    for _ in range(min(count, 65536)):
        item_id = _uint(iloc, p, idn)
        p += idn
        method = 0
        if ver in (1, 2):
            method = _uint(iloc, p, 2) & 15
            p += 2
        p += 2
        base = _uint(iloc, p, base_sz)
        p += base_sz
        extents = _uint(iloc, p, 2)
        p += 2
        chunks = []
        for _ in range(extents):
            p += idx_sz
            off = _uint(iloc, p, off_sz)
            p += off_sz
            length = _uint(iloc, p, len_sz)
            p += len_sz
            chunks.append((base + off, length))
        if item_id not in want:
            continue
        data = b""
        for off, length in chunks:
            if method == 0:
                fh.seek(off)
                data += _read(fh, length)
            elif method == 1 and idat is not None:
                data += idat[off:off + length]
        if data:
            out.xmp.append(data)


def _isobmff(fh: BinaryIO, out: _Blocks, size: int) -> None:
    fh.seek(8)
    brand = fh.read(4)
    out.mime = {b"heic": "image/heic", b"heix": "image/heic", b"heim": "image/heic",
                b"heis": "image/heic", b"avif": "image/avif", b"avis": "image/avif",
                b"qt  ": "video/quicktime"}.get(
        brand, "image/heif" if brand in _HEIF_BRANDS else "video/mp4")
    for btype, pos, n in _boxes(fh, 0, size):
        if btype == b"uuid" and n >= 16:
            fh.seek(pos)
            uid = fh.read(16)
            if uid == _UUID_C2PA:
                out.stores.append("ISOBMFF C2PA uuid box")
            elif uid == _UUID_XMP:
                out.xmp.append(_read(fh, n - 16))
        elif btype == b"meta" and n <= _MAX_BLOCK:
            fh.seek(pos)
            _heif_xmp(fh, fh.read(n), out)
        elif btype == b"moov" and n <= _MAX_BLOCK:
            for t2, p2, n2 in _boxes(fh, pos, pos + n):
                if t2 == b"udta":
                    for t3, p3, n3 in _boxes(fh, p2, p2 + n2):
                        if t3 == b"XMP_":
                            fh.seek(p3)
                            out.xmp.append(_read(fh, n3))
    out.known = True


def scan_blocks(path: str | Path) -> _Blocks:
    """Where a manifest store and XMP sit, from the file's bytes alone. The container
    is decided by the bytes, never the name. Raises OSError when the file cannot be
    opened; a truncated or malformed block keeps what was read before it."""
    out = _Blocks()
    with open(path, "rb") as fh:
        try:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(0)
            head = fh.read(16)
            if head[:3] == b"\xff\xd8\xff":
                _jpeg(fh, out)
            elif head[:8] == b"\x89PNG\r\n\x1a\n":
                _png(fh, out)
            elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
                _webp(fh, out)
            elif head[:4] in (b"II*\x00", b"MM\x00*"):
                _tiff(fh, out)
            elif head[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"uuid"):
                _isobmff(fh, out, size)
        except (OSError, struct.error, IndexError, ValueError):
            out.known = False         # read part way: let the library decide
    return out


# The Iptc4xmpExt:DigitalSourceType property, written as an attribute, as an element,
# or as an element with rdf:resource. The property name is matched exactly: the
# vocabulary's own namespace URI ends in "digitalsourcetype/", so a case-blind search
# for the name finds every URI of the vocabulary wherever it is mentioned.
_DST_URI = r"(https?://(?:cv\.iptc\.org/newscodes|c2pa\.org)/digitalsourcetype/[A-Za-z]+)"
_DST_IN_XMP = re.compile(
    r"\bDigitalSourceType\s*=\s*[\"']" + _DST_URI + r"[\"']"
    r"|<(?:[\w.-]+:)?DigitalSourceType\b[^>]*?rdf:resource\s*=\s*[\"']" + _DST_URI + r"[\"']"
    r"|<(?:[\w.-]+:)?DigitalSourceType(?:\s[^>]*)?>\s*" + _DST_URI + r"\s*<")
_REMOTE = re.compile(r"""provenance\s*=\s*["'](https?://[^"'<>\s]+)["']|"""
                     r"""<dcterms:provenance>\s*(https?://[^<\s]+)\s*<""")


def xmp_declaration(xmp: list[bytes]) -> dict | None:
    """An IPTC DigitalSourceType in XMP: an unsigned declaration, recorded as such."""
    for packet in xmp:
        found = _DST_IN_XMP.search(packet.decode("utf-8", "replace"))
        if found:
            uri = next(g for g in found.groups() if g)
            return {"uri": uri, "class": classify_dst(uri), "label": UNSIGNED,
                    "field": "XMP Iptc4xmpExt:DigitalSourceType"}
    return None


def _remote_reference(xmp: list[bytes]) -> str | None:
    for packet in xmp:
        found = _REMOTE.search(packet.decode("utf-8", "replace"))
        if found:
            return found.group(1) or found.group(2)
    return None


# -- the reader -----------------------------------------------------------------------

TRUST_DIR = Path(__file__).with_name("trust")


class TrustListError(ValueError):
    """A trust list the examiner configured could not be used."""


@dataclass(frozen=True)
class Anchor:
    """One PEM list of trust anchors. ``kind`` is c2pa-rs's trust_kind: "manifest"
    for claim signers, "tsa" for time-stamping authorities. ``uri`` goes to the
    reader as the list's trust_uri, and the reader names the one a trusted signer
    chained to in validation_results.trustListUri."""
    kind: str
    pem: bytes
    label: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.pem).hexdigest()

    @property
    def uri(self) -> str:
        return f"gleapp:{self.kind}:sha256:{self.sha256}"

    def describe(self) -> dict:
        return {"kind": self.kind, "label": self.label, "sha256": self.sha256}


_PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                              re.S)


def _certificates(pem: bytes) -> list[tuple[bytes, bytes]]:
    """(identity, PEM block) for each certificate in a PEM list. The identity is the
    certificate's DER, or the block's own text when its base64 does not decode: such a
    block is still passed on, and the reader is the one that reports it."""
    out = []
    for m in _PEM_CERTIFICATE.finditer(pem):
        body = b"".join(m.group(1).split())
        try:
            identity = base64.b64decode(body, validate=True)
        except binascii.Error:
            identity = body
        out.append((identity, m.group(0) + b"\n"))
    return out


@dataclass(frozen=True)
class TrustLists:
    """The anchors a file is read with."""
    anchors: tuple[Anchor, ...] = ()

    def by_uri(self, uri: str | None) -> Anchor | None:
        return next((a for a in self.anchors if uri and a.uri == uri), None)

    @property
    def tsa_uris(self) -> frozenset:
        return frozenset(a.uri for a in self.anchors if a.kind == "tsa")

    @cached_property
    def passed(self) -> tuple[dict, ...]:
        """What each list hands the reader: every certificate once, on the first signer
        list that holds it, else on the first TSA list, in the order given.

        c2pa-rs 0.91.0 keeps the anchor lists in a HashSet
        (Settings::merge_legacy_trust_anchors, sdk/src/settings/mod.rs:1074 and 1124 at
        e7cc666), so they are in a different order on every read, and it names the first
        list a chain reaches whatever its kind. 16 roots are on both C2PA lists, so a
        signer under one of them read as trusted, or through the TSA list as
        valid_untrusted, at random. Which certificates the reader trusts does not change:
        c2pa-rs checks a chain against every list whatever its kind, and every
        certificate left out of one list is still on another.

        Each entry is ``{"anchor", "pem", "certificates", "passed", "already_on"}``;
        ``pem`` is the list as given when nothing was left out of it, and empty when
        everything was, in which case it is not sent."""
        held = [_certificates(a.pem) for a in self.anchors]
        owner: dict[bytes, int] = {}
        for i in sorted(range(len(self.anchors)), key=lambda i: self.anchors[i].kind != "manifest"):
            for identity, _block in held[i]:
                owner.setdefault(identity, i)
        out = []
        for i, anchor in enumerate(self.anchors):
            kept: dict[bytes, bytes] = {}
            elsewhere: set[int] = set()
            for identity, block in held[i]:
                if owner[identity] == i:
                    kept.setdefault(identity, block)
                else:
                    elsewhere.add(owner[identity])
            if len(kept) == len(held[i]):         # nothing left out: the list as given
                pem = anchor.pem
            else:
                pem = b"".join(kept.values())
            out.append({"anchor": anchor, "pem": pem, "certificates": len(held[i]),
                        "passed": len(kept),
                        "already_on": [self.anchors[j].label for j in sorted(elsewhere)]})
        return tuple(out)

    def describe(self) -> list[dict]:
        """The lists a record was read with, and how much of each reached the reader."""
        out = []
        for p in self.passed:
            entry = {**p["anchor"].describe(), "certificates": p["certificates"],
                     "passed": p["passed"]}
            if p["already_on"]:
                entry["already_on"] = p["already_on"]
            out.append(entry)
        return out


def _pem_file(path: str | Path, what: str) -> bytes:
    name = Path(path).name
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise TrustListError(f"{what} {name}: {exc.strerror or type(exc).__name__}") from None
    if b"-----BEGIN CERTIFICATE-----" not in data:
        raise TrustListError(f"{what} {name}: no PEM certificate in it")
    return data


def _bundled() -> dict[str, Anchor]:
    manifest = json.loads((TRUST_DIR / "trust_lists.json").read_text(encoding="utf-8"))
    where = f"bundled, conformance-public {manifest['commit'][:7]}"
    names = {"manifest": "C2PA Trust List", "tsa": "C2PA TSA Trust List"}
    return {f["kind"]: Anchor(f["kind"], (TRUST_DIR / f["name"]).read_bytes(),
                              f"{names[f['kind']]} ({where})")
            for f in manifest["files"]}


def bundled_trust_lists() -> TrustLists:
    """The C2PA Trust List and C2PA TSA Trust List GLEAPP carries (gleapp/trust)."""
    b = _bundled()
    return TrustLists((b["manifest"], b["tsa"]))


def trust_lists(*, c2pa_list: str | Path | None = None, c2pa_tsa_list: str | Path | None = None,
                signer_anchors: str | Path | None = None,
                tsa_anchors: str | Path | None = None) -> TrustLists:
    """The anchors to read with. C2PA 2.2 §14.4.1 and §14.4.2: a validator's lists
    include the C2PA Trust List and the C2PA TSA Trust List, and should let the user
    add anchors of their own. So the examiner's anchors (``signer_anchors``,
    ``tsa_anchors``) are added to C2PA's, never put in their place; what can be put
    in place of the copies GLEAPP carries is a newer copy of C2PA's own lists
    (``c2pa_list``, ``c2pa_tsa_list``). Each is named by its file name, never its
    path, and every one has to hold a PEM certificate."""
    b = _bundled()
    anchors = []
    for kind, given, name in (("manifest", c2pa_list, "C2PA Trust List"),
                              ("tsa", c2pa_tsa_list, "C2PA TSA Trust List")):
        if given:
            anchors.append(Anchor(kind, _pem_file(given, name),
                                  f"{name} (examiner copy: {Path(given).name})"))
        else:
            anchors.append(b[kind])
    for kind, given, name in (("manifest", signer_anchors, "examiner signer anchors"),
                              ("tsa", tsa_anchors, "examiner TSA anchors")):
        if given:
            anchors.append(Anchor(kind, _pem_file(given, name), f"{name}: {Path(given).name}"))
    return TrustLists(tuple(anchors))


def configured_trust_lists() -> TrustLists:
    """The anchors the examiner set in the app config, or the bundled lists."""
    from . import appconfig  # pylint: disable=import-outside-toplevel
    return trust_lists(**appconfig.get_c2pa_trust_lists())


# The extended key usages c2pa-rs accepts on a signing certificate when it builds its
# trust policy with its own defaults (sdk/src/crypto/cose/valid_eku_oids.cfg, c2pa-rs
# 0.91.0). A reader opened from settings builds the policy without them unless
# trust.trust_config names them, and then a certificate whose only EKU is C2PA's own
# claim-signing one (C2PA 2.2 §14.4.1, the EKU the C2PA Trust List is for) is
# reported signingCredential.invalid, "certificate missing required EKU", and the
# manifest Invalid. Measured with a synthetic chain: Invalid without this, Valid
# with it, and Trusted once its root is an anchor.
VALID_EKUS = (
    "1.3.6.1.5.5.7.3.4",            # id-kp-emailProtection
    "1.3.6.1.5.5.7.3.36",           # id-kp-documentSigning
    "1.3.6.1.5.5.7.3.8",            # id-kp-timeStamping
    "1.3.6.1.5.5.7.3.9",            # id-kp-OCSPSigning
    "1.3.6.1.4.1.311.76.59.1.9",    # Microsoft C2PA signing
    "1.3.6.1.4.1.62558.2.1",        # c2pa-kp-claimSigning
)


def reader_settings(trust: TrustLists | None) -> dict:
    """The c2pa-python settings GLEAPP reads with: nothing fetched, nothing decoded
    that would fetch, the EKUs c2pa-rs itself accepts (``VALID_EKUS``) and the given
    anchors under ``trust.anchors`` (0.91 deprecates trust_anchors / user_anchors and
    0.92 removes them)."""
    anchors = [{"trust_anchors": p["pem"].decode("utf-8", "replace"),
                "trust_uri": p["anchor"].uri, "trust_kind": p["anchor"].kind}
               for p in (trust.passed if trust else ()) if p["pem"]]
    return {
        "verify": {"remote_manifest_fetch": False, "ocsp_fetch": False},
        "core": {"allowed_network_hosts": [], "decode_identity_assertions": False},
        "trust": {"anchors": anchors, "trust_config": "\n".join(VALID_EKUS) + "\n"},
    }


# c2pa-python looks for its native library in the working directory, and in its
# artifacts/ and libs/ folders and their platform subfolders, before its own package
# folder, and loads the first one it finds (c2pa/lib.py, _get_possible_search_paths,
# 0.38.0). A library left where GLEAPP was started would run inside it.
_C2PA_LIBRARY = {"darwin": "libc2pa_c.dylib", "linux": "libc2pa_c.so", "win32": "c2pa_c.dll"}


def _planted_c2pa_library() -> bool:
    if "c2pa" in sys.modules:            # already loaded: its library is in place
        return False
    names = {_C2PA_LIBRARY.get(sys.platform), os.environ.get("C2PA_LIBRARY_NAME")}
    names.discard(None)
    try:
        cwd = Path.cwd()
        for base in (cwd, cwd / "artifacts", cwd / "libs"):
            folders = [base] + ([p for p in base.iterdir() if p.is_dir()]
                                if base.is_dir() else [])
            if any((folder / name).exists() for folder in folders for name in names):
                return True
    except OSError:
        return False
    return False


def library_available() -> tuple[bool, str | None]:
    """Whether c2pa-python can be used, without loading it: the native library is
    only ever loaded by the process that reads with it."""
    if _planted_c2pa_library():
        return False, PLANTED
    if "c2pa" in sys.modules:
        return (True, None) if sys.modules["c2pa"] is not None else (False, NOT_CHECKED_LIBRARY)
    try:
        found = importlib.util.find_spec("c2pa") is not None
    except (ImportError, ValueError):
        found = False
    return (True, None) if found else (False, NOT_CHECKED_LIBRARY)


def _library():
    """The c2pa module, or the reason it cannot be used. Loads the native library."""
    if _planted_c2pa_library():
        return None, PLANTED
    try:
        import c2pa  # pylint: disable=import-outside-toplevel,import-error
    # pylint: disable-next=broad-exception-caught
    except Exception:  # noqa: BLE001 - absent, or its native library will not load
        return None, NOT_CHECKED_LIBRARY
    return c2pa, None


def library_version() -> str | None:
    """'c2pa-python X / c2pa-rs Y' when the library can be used, else None."""
    c2pa, _why = _library()
    if c2pa is None:
        return None
    from importlib import metadata  # pylint: disable=import-outside-toplevel
    try:
        py = metadata.version("c2pa-python")
    except metadata.PackageNotFoundError:
        py = "unknown"
    try:
        rs = c2pa.sdk_version()
    # pylint: disable-next=broad-exception-caught
    except Exception:  # noqa: BLE001
        rs = "unknown"
    return f"c2pa-python {py} / c2pa-rs {rs}"


def _scrub(text: str, path: str) -> str:
    from .imaging import scrub_local_paths  # pylint: disable=import-outside-toplevel
    return scrub_local_paths(text, path)[:_MAX_TEXT]


# -- one file: what the bytes settle, what the reader is asked, what is recorded -------

ABSENT_BY_SCAN = ("no manifest store and no reference to one in the file's metadata "
                  "blocks (read by GLEAPP)")
ABSENT_BY_READER = "the c2pa reader found no manifest store"
READER_STOPPED = "C2PA not checked: the reader stopped on this file"
UNSUPPORTED = "C2PA not checked: the c2pa reader does not support this format"
UNREADABLE = "C2PA not checked: the c2pa reader could not read the file"


def prescan(path: str | Path) -> tuple[dict, dict | None]:
    """(record, request). The part of a read GLEAPP does itself, from the bytes.
    ``request`` is None when the record is final; otherwise it is what the reader
    is to be asked: ``{"path", "mime", "remote"}``."""
    path = str(path)
    record: dict[str, Any] = {"state": "not_checked", "codes": _codes(None),
                              "active_dst": None, "dst_class": "none", "ingredients": [],
                              "xmp_dst": None, "store_in_bytes": None,
                              "library_version": None}
    try:
        blocks = scan_blocks(path)
    except OSError as exc:
        record["state_reason"] = "file could not be read: " + _scrub(
            f"{type(exc).__name__}: {exc}", path)
        return record, None
    record["xmp_dst"] = xmp_declaration(blocks.xmp)
    record["store_in_bytes"] = ", ".join(blocks.stores) or None
    remote = _remote_reference(blocks.xmp)
    if blocks.known and not blocks.stores and not remote:
        # the whole container was read and holds none: no reader is needed to say so
        record["state"] = "absent"
        record["state_reason"] = ABSENT_BY_SCAN
        return record, None
    usable, why = library_available()
    if not usable:
        record["state_reason"] = why
        return record, None
    return record, {"path": path, "mime": blocks.mime, "remote": remote}


def read_outcome(path: str, mime: str, settings: dict) -> dict:
    """What the c2pa reader makes of one file, as JSON. This is the only part of a
    read that loads the native library; ``read_batch`` runs it in a child process."""
    c2pa, why = _library()
    if c2pa is None:
        return {"kind": "unavailable", "reason": why}
    version = library_version()
    try:
        ctx = c2pa.Context(settings=c2pa.Settings.from_dict(settings))
        with open(path, "rb") as fh:
            reader = c2pa.Reader(mime, fh, context=ctx)
            try:
                store = json.loads(reader.json())
            finally:
                reader.close()
    except c2pa.C2paError.ManifestNotFound:
        return {"kind": "absent", "library_version": version}
    except c2pa.C2paError.RemoteManifest:
        return {"kind": "remote", "library_version": version}
    except c2pa.C2paError.NotSupported:
        return {"kind": "unsupported", "library_version": version}
    except (c2pa.C2paError.Io, c2pa.C2paError.FileNotFound) as exc:
        return {"kind": "io", "reason": _scrub(str(exc), path), "library_version": version}
    except c2pa.C2paError as exc:       # about the manifest store itself
        return {"kind": "malformed", "reason": _scrub(str(exc), path),
                "library_version": version}
    # pylint: disable-next=broad-exception-caught
    except Exception as exc:  # noqa: BLE001 - recorded, never raised into the pipeline
        return {"kind": "error", "library_version": version,
                "reason": "reader error: " + _scrub(f"{type(exc).__name__}: {exc}", path)}
    return {"kind": "store", "store": store, "library_version": version}


def finish(record: dict, request: dict, outcome: dict, trust: TrustLists) -> dict:
    """``record`` completed with what the reader made of the file."""
    kind = outcome.get("kind")
    record["library_version"] = outcome.get("library_version")
    record["trust_lists"] = trust.describe()
    if kind == "store":
        record.update(parse_manifest_store(outcome["store"], tsa_uris=trust.tsa_uris))
        vouched = trust.by_uri(record.get("trust_list_uri"))
        record["trusted_by"] = vouched.label if vouched else None
        record["trust_list_sha256"] = vouched.sha256 if vouched else None
    elif kind == "absent":
        record["state"] = "absent"
        record["state_reason"] = ABSENT_BY_READER
    elif kind == "remote":
        record["state_reason"] = REMOTE_NOT_FETCHED
        record["remote_url"] = request.get("remote")
    elif kind == "malformed":
        record["state"] = "malformed"
        record["state_reason"] = outcome.get("reason")
    elif kind == "crashed":
        record["state_reason"] = READER_STOPPED
    elif kind == "unsupported":
        record["state_reason"] = UNSUPPORTED
    elif kind == "io":
        record["state_reason"] = f"{UNREADABLE}: {outcome.get('reason') or ''}".rstrip(": ")
    else:                               # unavailable, error
        record["state_reason"] = outcome.get("reason") or "reader error"
    return record


def _resolve(trust: TrustLists | None) -> TrustLists:
    return configured_trust_lists() if trust is None else trust


def read_provenance(path: str | Path, *, trust: TrustLists | None = None) -> dict:
    """The provenance record of one file, JSON-serializable, read in this process.
    Never writes to ``path``. ``trust`` defaults to ``configured_trust_lists()``;
    pass ``TrustLists()`` to read with no anchors at all. ``read_batch`` reads many
    files with the reader in a child process instead."""
    record, request = prescan(path)
    if request is None:
        return record
    try:
        trust = _resolve(trust)
    except TrustListError as exc:
        # reading with the bundled lists instead would record a result the
        # examiner did not ask for
        record["state_reason"] = TRUST_UNREADABLE + _scrub(str(exc), str(path))
        return record
    outcome = read_outcome(request["path"], request["mime"], reader_settings(trust))
    return finish(record, request, outcome, trust)


TRUST_UNREADABLE = "C2PA not checked: trust list could not be read: "


# -- many files: the reader in a child process ----------------------------------------

def worker_command() -> list[str]:
    from .workers import worker_command as _command  # pylint: disable=import-outside-toplevel
    return _command("c2paworker")


def _run_reader(requests: list[dict], settings: dict, *, timeout: int, depth: int = 0
                ) -> dict[str, dict]:
    """{path: outcome} from the reader process. The paths and the settings go on its
    stdin, never on its command line or in a file. A child that stops before
    answering for every file is run again on halves of what it left, so the file it
    stopped on ends alone and is the only one recorded as stopping it."""
    if not requests:
        return {}
    payload = json.dumps({"settings": settings,
                          "items": [{"path": r["path"], "mime": r["mime"]} for r in requests]})
    try:
        done = subprocess.run(worker_command(), input=payload, capture_output=True,
                              text=True, encoding="utf-8", timeout=timeout, check=False)
        lines = (done.stdout or "").splitlines()
    except (subprocess.TimeoutExpired, OSError):
        lines = []
    wanted = {r["path"] for r in requests}
    out: dict[str, dict] = {}
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("path") in wanted:
            out[item["path"]] = item.get("outcome") or {"kind": "error"}
    left = [r for r in requests if r["path"] not in out]
    if left:
        if len(left) == 1 or depth >= 12:
            for r in left:
                out[r["path"]] = {"kind": "crashed"}
        else:
            mid = len(left) // 2
            for half in (left[:mid], left[mid:]):
                out.update(_run_reader(half, settings, timeout=timeout, depth=depth + 1))
    return out


def read_batch(paths: Iterable[str | Path], *, trust: TrustLists | None = None,
               timeout: int = 600) -> dict[str, dict]:
    """{path: record} for many files, with the c2pa reader in a child process.
    Raises TrustListError, before anything is read, when a configured list cannot
    be read."""
    paths = [str(p) for p in paths]
    pre = {p: prescan(p) for p in paths}
    requests = [req for _rec, req in pre.values() if req is not None]
    out = {p: rec for p, (rec, req) in pre.items() if req is None}
    if not requests:
        return out
    trust = _resolve(trust)
    outcomes = _run_reader(requests, reader_settings(trust), timeout=timeout)
    for req in requests:
        rec, _req = pre[req["path"]]
        out[req["path"]] = finish(rec, req, outcomes.get(req["path"], {"kind": "crashed"}),
                                  trust)
    return out


def columns(record: dict) -> dict:
    """The four columns ``files`` keeps for a record."""
    return {"c2pa_state": record["state"],
            "c2pa_dst_class": record.get("dst_class") or "none",
            "c2pa_signer": signer_text(record.get("signer")) or None,
            "c2pa_info": json.dumps(record, sort_keys=True)}


EMPTY_COLUMNS = {"c2pa_state": None, "c2pa_dst_class": None, "c2pa_signer": None,
                 "c2pa_info": None}


# -- words for the surfaces -----------------------------------------------------------

def _term(uri: str) -> str:
    return str(uri).rstrip("/").rsplit("/", 1)[-1]


def _term_text(uri: str, cls: str | None) -> str:
    """'term (class)', the term marked when IPTC has retired it."""
    term = _term(uri)
    if term in RETIRED_TERMS and _IPTC_NAMESPACE in str(uri).lower():
        term += ", retired by IPTC"
    return f"{term} ({DST_CLASS_LABELS.get(cls, '')})"


def _ingredient_lines(ingredients: list, depth: int = 0) -> list[str]:
    lines = []
    for ing in ingredients or []:
        dst = ing.get("dst")
        what = _term_text(dst, ing.get("dst_class")) if dst else "no source type declared"
        state = STATE_SHORT.get(ing.get("state"), ing.get("state") or "")
        lines.append(f"{'  ' * depth}{ing.get('title') or 'untitled'}: {what}; {state}")
        lines += _ingredient_lines(ing.get("ingredients") or [], depth + 1)
    return lines


def _actions_text(record: dict) -> str | None:
    """The declared actions, one a line, as the manifest names them; None when the
    record has no manifest to declare any."""
    if "actions" not in record:
        # read by a GLEAPP that did not keep them: not the same as none declared
        return ("not recorded by the GLEAPP that read this file "
                "(gleapp provenance --force reads it again)"
                if record.get("active_manifest") else None)
    lines = [(a.get("action") or "(no action named)")
             + (f" (software agent: {a['software_agent']})" if a.get("software_agent") else "")
             for a in record["actions"] or [] if isinstance(a, dict)]
    if record.get("actions_omitted"):
        lines.append(f"and {record['actions_omitted']} more")
    if not lines:
        return "none declared"
    if record.get("state") not in ("valid_untrusted", "trusted"):
        # C2PA 2.2 §15.3, as for the declared source type
        lines.insert(0, "not backed by a valid signature:")
    return "\n".join(lines)


def describe(record: dict | None) -> list[tuple[str, str]]:
    """(label, value) rows for a record, in the words every surface uses: what the
    file declares, who signed it, whether the signature validates and whether the
    signer is on a trust list GLEAPP holds. Never a finding about the content."""
    if not record:
        return [("State", "Not read yet")]
    rows: list[tuple[str, str]] = []
    label = STATE_LABELS.get(record.get("state"), record.get("state") or "")
    reason = record.get("state_reason")
    rows.append(("State", f"{label}: {reason}" if reason else label))
    if signer_text(record.get("signer")):
        rows.append(("Signer", signer_text(record.get("signer"))))
    if record.get("signed_time"):
        rows.append(("Time-stamp", str(record["signed_time"])))
    if record.get("claim_generator"):
        rows.append(("Claim generator", str(record["claim_generator"])))
    if record.get("active_dst"):
        text = _term_text(record["active_dst"], record.get("dst_class"))
        if not record.get("dst_signed_valid"):
            text += ", not backed by a valid signature"
        rows.append(("Declared source type", text))
    actions = _actions_text(record)
    if actions:
        rows.append(("Declared actions", actions))
    if record.get("trusted_by"):
        rows.append(("Signer's trust list", str(record["trusted_by"])))
    if record.get("hard_binding_mismatch"):
        rows.append(("Hard binding", "does not match the content the manifest was signed "
                     "for (for example, the content changed after signing, or the manifest "
                     "belongs to other content)"))
    failures = [c.get("code") for c in (record.get("codes") or {}).get("failure", [])
                if isinstance(c, dict)]
    if failures:
        rows.append(("Validation failures", ", ".join(failures)))
    lines = _ingredient_lines(record.get("ingredients") or [])
    if lines:
        rows.append(("Ingredients", "\n".join(lines)))
    xmp = record.get("xmp_dst")
    if xmp:
        rows.append(("XMP source type",
                     f"{_term_text(xmp.get('uri', ''), xmp.get('class'))}, {UNSIGNED}"))
    if record.get("remote_url"):
        rows.append(("Remote manifest", str(record["remote_url"])))
    if record.get("store_in_bytes"):
        rows.append(("Manifest store in", str(record["store_in_bytes"])))
    if record.get("library_version"):
        rows.append(("Read with", str(record["library_version"])))
    return rows


DECLARATION_NOTE = "A declaration, not a finding."
_VALID = ("valid_untrusted", "trusted")


def _ai_ingredient(ingredients: Any) -> dict | None:
    for ing in ingredients if isinstance(ingredients, list) else []:
        if not isinstance(ing, dict):
            continue
        if ing.get("dst") and ing.get("dst_class") in AI_CLASSES:
            return ing
        found = _ai_ingredient(ing.get("ingredients"))
        if found:
            return found
    return None


def ai_declaration(record: dict | None) -> dict | None:
    """What a file declares about generative AI, for the gallery's mark, or None when
    nothing does: the file's own manifest first, then its XMP, then the first
    ingredient that declares it. ``backed`` says whether a valid signature stands
    behind the declaration, ``text`` says so in a list cell and ``title`` in full.
    A file that declares nothing gets no mark: absence says nothing either way."""
    if not record:
        return None
    if record.get("active_dst") and record.get("dst_class") in AI_CLASSES:
        state = STATE_LABELS.get(record.get("state"), record.get("state") or "")
        what = _term_text(record["active_dst"], record["dst_class"])
        backed = record.get("state") in _VALID
        return {"badge": "AI declared", "backed": backed,
                "text": "AI declared" if backed else
                        "AI declared, not backed by a valid signature",
                "title": f"Declared by the file's Content Credentials: {what}"
                         + (f"; {state}. " if backed else
                            f", not backed by a valid signature ({state}). ")
                         + DECLARATION_NOTE}
    xmp = record.get("xmp_dst")
    if isinstance(xmp, dict) and xmp.get("uri") and xmp.get("class") in AI_CLASSES:
        return {"badge": "AI declared", "backed": False, "text": "AI declared, unsigned (XMP)",
                "title": f"Declared in the file's XMP: {_term_text(xmp['uri'], xmp['class'])}, "
                         f"{UNSIGNED}. {DECLARATION_NOTE}"}
    ing = _ai_ingredient(record.get("ingredients"))
    if ing:
        state = STATE_LABELS.get(ing.get("state"), ing.get("state") or "")
        backed = ing.get("state") in _VALID
        return {"badge": "AI in ingredient", "backed": backed,
                "text": "AI in ingredient" if backed else
                        "AI in ingredient, not backed by a valid signature",
                "title": f'Declared by the ingredient "{ing.get("title") or "untitled"}": '
                         f"{_term_text(ing['dst'], ing['dst_class'])}"
                         + (f"; {state}. " if backed else
                            f", not backed by a valid signature ({state}). ")
                         + DECLARATION_NOTE}
    return None


def describe_text(record: dict | None) -> str:
    """``describe`` as lines of 'label: value', for a report cell."""
    return "\n".join(f"{k}: {v}" for k, v in describe(record))


def xmp_text(record: dict | None) -> str:
    """The unsigned XMP declaration's class, labelled as such, or ''."""
    xmp = (record or {}).get("xmp_dst")
    return f"{xmp.get('class')} ({UNSIGNED})" if xmp else ""


def _reclassify(ingredients: Any) -> None:
    for ing in ingredients if isinstance(ingredients, list) else []:
        if isinstance(ing, dict):
            if "dst_class" in ing:
                ing["dst_class"] = classify_dst(ing.get("dst"))
            _reclassify(ing.get("ingredients"))


def load(info: str | None) -> dict | None:
    """The record kept in ``files.c2pa_info``, or None, with each class worked out
    again from the URI it was decided from (``DST_VOCABULARY``). The stored text is
    not changed: it stays the record as it was read."""
    if not info:
        return None
    try:
        rec = json.loads(info)
    except (TypeError, ValueError):
        return None
    if not isinstance(rec, dict):
        return None
    if "dst_class" in rec:
        rec["dst_class"] = classify_dst(rec.get("active_dst"))
    _reclassify(rec.get("ingredients"))
    xmp = rec.get("xmp_dst")
    if isinstance(xmp, dict) and "class" in xmp:
        xmp["class"] = classify_dst(xmp.get("uri"))
    return rec
