#!/usr/bin/env python3
"""Supply-chain controls for the documentation site (issue #1423).

The docs site has its own toolchain (mdBook, a theme script, GitHub Actions,
GitHub Pages) separate from the contract's Cargo graph. This script brings it
under the same class of checks the contract gets; see
docs/security/docs-site-supply-chain.md for the threat model.

Subcommands:
  check-pins           every `uses:` in docs.yml is pinned to a full commit SHA,
                       mdBook is pinned to MDBOOK_VERSION, docs-site Python is
                       stdlib-only, and the theme loads nothing external.
  fetch-mdbook-lock D  download the pinned mdBook crate, verify its SHA-256
                       against MDBOOK_CRATE_SHA256 (the crates.io index
                       checksum), and extract its Cargo.lock into D for
                       `cargo audit` / `cargo deny`.
  seal BOOK            fail if built HTML loads an external script/stylesheet
                       without Subresource Integrity, then write
                       BOOK/integrity.json (SHA-256 of every file) and print
                       the root digest.
  audit-ignores        print `--ignore <ID>` flags for cargo audit; fail if any
                       MDBOOK_AUDIT_IGNORES entry has expired.
  verify BOOK          recompute every hash and the root digest and compare
                       with BOOK/integrity.json (or --digest <hex>).

Pure Python standard library. `--self-test` exercises seal/verify/check-pins.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/docs.yml"

# Bumping mdBook: update both values (the checksum is the `cksum` field of the
# version's line in https://index.crates.io/md/bo/mdbook) and the version in
# docs.yml; `check-pins` fails if they disagree.
MDBOOK_VERSION = "0.5.4"
MDBOOK_CRATE_SHA256 = "5f68ffebcd0b9a4eb72aaacc4342bc94e1d63c01893b7c921437f6ef02443699"

# Time-boxed advisory exceptions for mdBook's dependency graph, under the same
# rules as deny.toml (docs/dependency-update-policy.md § Advisory exception
# expiry): a reason, an owner, and an expiry at most 90 days out. An expired
# entry fails `audit-ignores`, and so the `toolchain-audit` job.
MDBOOK_AUDIT_IGNORES = [
    {
        "id": "RUSTSEC-2026-0204",
        "reason": "crossbeam-epoch <0.9.20: invalid pointer deref in the fmt::Pointer impl of "
        "Atomic/Shared. Reached via mdbook -> ignore -> crossbeam-deque, neither of which "
        "formats those pointers with {:p}. No mdBook release ships the fix yet.",
        "owner": "tools/docs-site maintainers",
        "expires": "2027-01-14",
    },
]

MANIFEST = "integrity.json"
SHA_PIN = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-f]{40})(\s+#.*)?$")
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
EXTERNAL_URL = re.compile(r"""(?:https?:)?//[^\s"'`)]+""")
EXTERNAL_TAG = re.compile(
    r"<(script|link)\b[^>]*?\b(?:src|href)\s*=\s*[\"'](?:https?:)?//[^\"']+[\"'][^>]*>", re.I
)


# ── check-pins ───────────────────────────────────────────────────────────────

def check_pins(workflow: Path = WORKFLOW, docs_site: Path = HERE) -> list[str]:
    errors: list[str] = []
    text = workflow.read_text(encoding="utf-8")
    for n, line in enumerate(text.splitlines(), 1):
        m = USES.match(line)
        if m and not m.group(1).startswith("./") and not SHA_PIN.match(line):
            errors.append(f"{workflow.name}:{n}: action not pinned to a full commit SHA: {m.group(1)}")
    found = re.findall(r"mdbook@([0-9][0-9A-Za-z.+-]*)", text)
    if found != [MDBOOK_VERSION] * len(found) or not found:
        errors.append(f"{workflow.name}: mdBook must be installed as mdbook@{MDBOOK_VERSION} (found {found})")

    stdlib = set(sys.stdlib_module_names)
    for py in sorted(docs_site.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".")[0]
                if top not in stdlib and top != "__future__":
                    errors.append(f"{py.name}: non-stdlib import `{name}` (docs-site tooling is stdlib-only)")

    for js in sorted((docs_site / "theme").rglob("*")):
        if js.is_file():
            for url in EXTERNAL_URL.findall(js.read_text(encoding="utf-8", errors="replace")):
                errors.append(f"theme/{js.name}: references an external URL {url}")
    return errors


# ── fetch-mdbook-lock ────────────────────────────────────────────────────────

def fetch_mdbook_lock(out: Path) -> Path:
    url = f"https://static.crates.io/crates/mdbook/mdbook-{MDBOOK_VERSION}.crate"
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 (fixed https URL)
        data = r.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != MDBOOK_CRATE_SHA256:
        raise SystemExit(f"mdbook-{MDBOOK_VERSION}.crate sha256 {digest} != pinned {MDBOOK_CRATE_SHA256}")
    member = f"mdbook-{MDBOOK_VERSION}/Cargo.lock"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        lock = tar.extractfile(member)
        if lock is None:
            raise SystemExit(f"{member} missing from the published crate")
        out.mkdir(parents=True, exist_ok=True)
        path = out / "Cargo.lock"
        path.write_bytes(lock.read())
    print(f"verified mdbook-{MDBOOK_VERSION}.crate ({digest}); lockfile at {path}")
    return path


def audit_ignores(today: str | None = None) -> list[str]:
    import datetime

    today = today or datetime.date.today().isoformat()
    expired = [e["id"] for e in MDBOOK_AUDIT_IGNORES if e["expires"] < today]
    if expired:
        raise SystemExit(f"expired docs-toolchain advisory exception(s): {', '.join(expired)}")
    return [arg for e in MDBOOK_AUDIT_IGNORES for arg in ("--ignore", e["id"])]


# ── seal / verify ────────────────────────────────────────────────────────────

def unpinned_external_assets(book: Path) -> list[str]:
    errors = []
    for page in sorted(book.rglob("*.html")):
        for tag in EXTERNAL_TAG.finditer(page.read_text(encoding="utf-8", errors="replace")):
            text = tag.group(0)
            is_style_or_script = tag.group(1).lower() == "script" or re.search(r"rel\s*=\s*[\"']?stylesheet", text, re.I)
            if is_style_or_script and not re.search(r"\bintegrity\s*=\s*[\"']sha(256|384|512)-", text, re.I):
                errors.append(f"{page.relative_to(book)}: external asset without SRI: {text[:120]}")
    return errors


def file_hashes(book: Path) -> dict[str, str]:
    return {
        p.relative_to(book).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(book.rglob("*"))
        if p.is_file() and p.name != MANIFEST
    }


def root_digest(files: dict[str, str]) -> str:
    lines = "".join(f"{h}  {path}\n" for path, h in sorted(files.items()))
    return hashlib.sha256(lines.encode()).hexdigest()


def seal(book: Path) -> str:
    errors = unpinned_external_assets(book)
    if errors:
        raise SystemExit("\n".join(errors))
    files = file_hashes(book)
    digest = root_digest(files)
    manifest = {"algorithm": "sha256", "root_digest": digest, "files": files}
    (book / MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    print(digest)
    return digest


def verify(book: Path, digest: str | None = None) -> list[str]:
    manifest = json.loads((book / MANIFEST).read_text())
    expected_root = digest or manifest["root_digest"]
    actual = file_hashes(book)
    errors = []
    if root_digest(manifest["files"]) != manifest["root_digest"]:
        errors.append("integrity.json: root_digest does not match its own file list")
    for path in sorted(set(manifest["files"]) | set(actual)):
        if manifest["files"].get(path) != actual.get(path):
            errors.append(f"{path}: {'missing' if path not in actual else 'unexpected' if path not in manifest['files'] else 'modified'}")
    if root_digest(actual) != expected_root:
        errors.append(f"root digest {root_digest(actual)} != expected {expected_root}")
    return errors


# ── self-test ────────────────────────────────────────────────────────────────

def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        book = Path(tmp) / "book"
        (book / "api").mkdir(parents=True)
        (book / "index.html").write_text('<script src="book.js"></script>')
        (book / "api/x.html").write_text("ok")
        d = seal(book)
        assert verify(book) == [] and verify(book, d) == []
        (book / "api/x.html").write_text("tampered")
        assert any("modified" in e for e in verify(book))
        (book / "api/x.html").write_text("ok")
        (book / "evil.js").write_text("x")
        assert any("unexpected" in e for e in verify(book))
        (book / "evil.js").unlink()
        assert verify(book, "0" * 64) != []

        (book / "index.html").write_text('<script src="https://cdn.example/x.js"></script>')
        try:
            seal(book)
            raise AssertionError("external script without SRI was accepted")
        except SystemExit:
            pass
        (book / "index.html").write_text(
            '<script src="https://cdn.example/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
        )
        seal(book)

        wf = Path(tmp) / "docs.yml"
        site = Path(tmp) / "site"
        (site / "theme").mkdir(parents=True)
        (site / "build.py").write_text("import json\nfrom pathlib import Path\n")
        (site / "theme/a.js").write_text("fetch(root + 'versions.json')")
        wf.write_text(f"- uses: actions/checkout@{'a' * 40}  # v4\n  with: {{tool: mdbook@{MDBOOK_VERSION}}}\n")
        assert check_pins(wf, site) == [], check_pins(wf, site)
        wf.write_text(f"- uses: actions/checkout@v4\n  tool: mdbook@{MDBOOK_VERSION}\n")
        assert any("not pinned" in e for e in check_pins(wf, site))
        (site / "build.py").write_text("import yaml\n")
        (site / "theme/a.js").write_text("load('https://evil.example/x.js')")
        errs = check_pins(wf, site)
        assert any("non-stdlib" in e for e in errs) and any("external URL" in e for e in errs)

    assert audit_ignores("2000-01-01")[0] == "--ignore"
    try:
        audit_ignores("9999-12-31")
        raise AssertionError("expired advisory exception was accepted")
    except SystemExit:
        pass
    print("self-test OK")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check-pins")
    sub.add_parser("audit-ignores")
    f = sub.add_parser("fetch-mdbook-lock")
    f.add_argument("out", type=Path)
    s = sub.add_parser("seal")
    s.add_argument("book", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("book", type=Path)
    v.add_argument("--digest", help="expected root digest, e.g. from the docs workflow run summary")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.cmd == "check-pins":
        errors = check_pins()
        for e in errors:
            print(f"error: {e}")
        print(f"docs-site toolchain pins: {len(errors)} problem(s)")
        return 1 if errors else 0
    if args.cmd == "audit-ignores":
        print(" ".join(audit_ignores()))
        return 0
    if args.cmd == "fetch-mdbook-lock":
        fetch_mdbook_lock(args.out)
        return 0
    if args.cmd == "seal":
        seal(args.book)
        return 0
    if args.cmd == "verify":
        errors = verify(args.book, args.digest)
        for e in errors:
            print(f"error: {e}")
        print("integrity: OK" if not errors else f"integrity: {len(errors)} problem(s)")
        return 1 if errors else 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
