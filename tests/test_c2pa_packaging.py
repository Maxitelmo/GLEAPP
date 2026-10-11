"""c2pa-python is an optional extra, and no build of GLEAPP carries it.

Reading Content Credentials needs c2pa-python, whose native library is compiled from
c2pa-rs and its Rust dependencies. Upstream publishes no lockfile or third-party
notice for that library (checked for c2pa-python 0.38.0 / c2pa-rs 0.91.0 on
2026-10-06), so a frozen build could not carry a notice that is provably complete.
It is therefore an extra (``pip install -e ".[provenance]"``), not a requirement,
and a build that happens to have it installed must not pick it up half-way. The
measurements are in "C2PA reading is optional" in .claude/rules/gleapp-cross-platform.md.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(*parts: str) -> str:
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def test_c2pa_python_is_an_extra_pinned_below_the_next_minor():
    """0.92.0 removes the trust settings 0.91 deprecated (trust.trust_anchors and
    trust.user_anchors), and the reader's JSON and state rules have changed between
    minors, so an upgrade is a decision, not something pip makes."""
    extra = re.search(r'^provenance = \[(.*)\]$', _text("pyproject.toml"), re.M)
    assert extra, "pyproject.toml has no [provenance] extra"
    assert extra.group(1) == '"c2pa-python>=0.38,<0.39"'


def test_the_requirements_do_not_carry_it():
    assert "c2pa" not in _text("requirements.txt").lower()


def test_the_frozen_build_excludes_it():
    """PyInstaller follows an import even inside a function, so a build environment
    with the extra installed would collect the c2pa package without the native
    library it loads through ctypes, and its notice would be empty."""
    spec = _text("packaging", "gleapp.spec")
    excludes = re.search(r"excludes=\[(.*?)\],\n", spec, re.S).group(1)
    assert '"c2pa"' in excludes


def test_the_frozen_build_drops_its_metadata_too():
    """The exclude keeps the code out, not the dist-info: PyInstaller copies it
    because provenance.library_version() asks importlib.metadata for "c2pa-python"
    by name, and a build beside the extra carried c2pa_python-0.38.0.dist-info."""
    spec = _text("packaging", "gleapp.spec")
    found = re.search(r'^_C2PA_METADATA = re\.compile\(r"(.+?)", re\.I\)$', spec, re.M)
    assert found, "the spec does not drop c2pa-python's metadata"
    metadata = re.compile(found.group(1), re.I)
    for dest in ("c2pa_python-0.38.0.dist-info", "c2pa_python-0.38.0.dist-info/RECORD",
                 "c2pa_python-0.38.0.dist-info\\METADATA", "C2PA_Python-1.0.dist-info/WHEEL"):
        assert metadata.match(dest), dest
    for dest in ("gleapp/trust/LICENSE-c2pa-trust-lists", "gleapp/trust/C2PA-TRUST-LIST.pem",
                 "c2pa_pythonic-1.0.dist-info/METADATA", "x/c2pa_python-0.38.0.dist-info/RECORD"):
        assert not metadata.match(dest), dest
    assert re.search(r"^a\.datas = \[d for d in a\.datas if not _C2PA_METADATA\.match\(",
                     spec, re.M)
    # what puts it there: if this call goes, so can the filter
    assert 'metadata.version("c2pa-python")' in _text("gleapp", "provenance.py")


def test_ci_runs_the_suite_with_the_library_and_without_it():
    """The Linux and Windows jobs install the extra, so the signed-fixture tests run;
    the runtime-contract matrix (3.10 to 3.14) does not, so the 'library unavailable'
    path runs as an examiner without it would meet it."""
    workflows = ROOT / ".github" / "workflows"
    for name in ("test_cases.yml", "windows_smoke.yml"):
        assert '".[dev,provenance]"' in (workflows / name).read_text(encoding="utf-8"), name
    assert "provenance" not in (workflows / "python_runtime_contract.yml").read_text(
        encoding="utf-8")
