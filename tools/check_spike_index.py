#!/usr/bin/env python3
"""Keep docs/spike-index.md and the per-document spike markers in sync (issue #1424).

Fails when:
  * a markdown file under docs/ carries a `**Spike status:**` marker but no
    index row links to it;
  * an index row links to a document that has no marker;
  * the status in the index row differs from the marker's status;
  * a status is not one of the documented vocabulary;
  * a `still-open` row/marker names neither a tracking issue (`#N`) nor an
    explicit `pending` placeholder, or a `superseded` marker links to nothing.

`pending` placeholders (still-open spikes whose issue is drafted in the
index's "Open items" table but not yet filed) are printed as warnings.

Pure Python, no network. Usage: python3 tools/check_spike_index.py [--self-test]
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"concluded-adopted", "concluded-rejected", "superseded", "still-open", "abandoned"}
MARKER = re.compile(r"^> \*\*Spike status:\*\* `([^`]+)`.*$", re.M)
ROW = re.compile(r"^\| \[[^\]]+\]\(([^)#]+)(?:#[^)]*)?\) \|[^|]*\| `([^`]+)` \|([^|]*)\|", re.M)


def markers(docs: Path) -> dict[str, list[tuple[str, str]]]:
    """Map doc path (relative to docs/) -> [(status, marker block text)]."""
    found: dict[str, list[tuple[str, str]]] = {}
    for path in sorted(docs.rglob("*.md")):
        if path.name == "spike-index.md":
            continue
        text = path.read_text(encoding="utf-8")
        for m in MARKER.finditer(text):
            block = text[m.start(): text.find("\n\n", text.find("\n>\n", m.end()) + 3)]
            found.setdefault(path.relative_to(docs).as_posix(), []).append((m.group(1), block))
    return found


def check(docs: Path, warnings: list[str] | None = None) -> list[str]:
    errors: list[str] = []
    warnings = warnings if warnings is not None else []
    index = (docs / "spike-index.md").read_text(encoding="utf-8")
    rows = {}
    for target, status, resolution in ROW.findall(index):
        rows.setdefault(target, []).append((status, resolution))
    found = markers(docs)

    for doc, entries in found.items():
        for status, block in entries:
            if status not in STATUSES:
                errors.append(f"{doc}: unknown spike status `{status}`")
            if status == "still-open" and not re.search(r"Tracked in: #\d+", block):
                if re.search(r"Tracked in: pending", block):
                    warnings.append(f"{doc}: `still-open` spike has no tracking issue yet (pending)")
                else:
                    errors.append(f"{doc}: `still-open` marker has no `Tracked in: #N` or `pending`")
            if status == "superseded" and "](" not in block:
                errors.append(f"{doc}: `superseded` marker links to nothing")
        if doc not in rows:
            errors.append(f"{doc}: has a spike marker but no row in spike-index.md")
    for doc, entries in rows.items():
        if doc not in found:
            errors.append(f"spike-index.md: row for {doc} but the document has no marker")
            continue
        if sorted(s for s, _ in entries) != sorted(s for s, _ in found[doc]):
            errors.append(f"spike-index.md: status for {doc} differs from its marker(s)")
        for status, resolution in entries:
            if status == "still-open" and not re.search(r"#\d+|pending", resolution):
                errors.append(f"spike-index.md: `still-open` row for {doc} has no tracking issue")
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp)
        good = "> **Spike status:** `still-open` · x\n>\n> **Outcome:** y. Tracked in: #7.\n\nbody\n"
        (docs / "a.md").write_text("# A\n\n" + good)
        (docs / "spike-index.md").write_text("| [a.md](a.md) | t | `still-open` | tracked in #7 |\n")
        assert check(docs) == [], check(docs)
        (docs / "a.md").write_text("# A\n\n" + good.replace("#7", "TBD"))
        assert any("Tracked in" in e for e in check(docs))
        (docs / "a.md").write_text("# A\n\n" + good.replace("#7", "pending"))
        warned: list[str] = []
        assert check(docs, warned) == [] and warned
        (docs / "a.md").write_text("# A\n\n" + good)
        (docs / "b.md").write_text("# B\n\n" + good)
        assert any("b.md" in e for e in check(docs))
        (docs / "b.md").unlink()
        (docs / "spike-index.md").write_text("| [a.md](a.md) | t | `superseded` | #7 |\n")
        assert any("differs" in e for e in check(docs))
    print("self-test OK")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    warnings: list[str] = []
    errors = check(ROOT / "docs", warnings)
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    print(f"spike index: {len(markers(ROOT / 'docs'))} marked document(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
