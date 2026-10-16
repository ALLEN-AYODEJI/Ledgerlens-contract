# Documentation Site Supply Chain: Threat Model and Controls

Issue #1423. The versioned documentation site (`.github/workflows/docs.yml`,
[CONTRIBUTING.md § Docs site](../../CONTRIBUTING.md)) is a published artefact
that integrators treat as authoritative: contract addresses, interface
signatures, verification procedures and code examples are copied from it. A
compromised site build or host could serve a fake address, a fake "verified"
claim or an altered example without touching the contract.

This document extends the scope of the contract's supply-chain controls —
[reproducible-builds.md § Dependency license policy & SBOM](../reproducible-builds.md#dependency-license-policy--sbom),
[dependency-update-policy.md](../dependency-update-policy.md), the `audit`,
`dependency-license` and `supply-chain` jobs in `ci.yml`, and
[`SECURITY.md`](../../SECURITY.md) — to the site's toolchain, which was
previously out of scope only because it produces no WASM.

## Inventory

| Component | What it is | How it is obtained | Pin before #1423 | Pin now |
|---|---|---|---|---|
| `tools/docs-site/build.py`, `check_links.py` | Assemble the mdBook source, check links | In-repo, Python stdlib only | n/a | Stdlib-only enforced by `supply_chain.py check-pins` |
| `tools/docs-site/theme/version-selector.js` | Only custom script on every page | In-repo | n/a | No external URLs allowed (`check-pins`) |
| mdBook | Static site generator; its bundled theme supplies all other JS/CSS (highlight.js, clipboard, elasticlunr, fonts) | Prebuilt binary via `taiki-e/install-action` | `0.4.40` | `0.5.4`; crate checksum `5f68ffeb…` pinned in `supply_chain.py` |
| mdBook's Rust dependency graph | ~200 crates compiled into the binary | Its published `Cargo.lock` | not scanned | `cargo audit` in the `toolchain-audit` job |

**Assessment finding.** Scanning the previously pinned mdBook 0.4.40 lockfile reported 10 RustSec vulnerabilities plus yanked and unsound crates (`tokio`, `bytes`, `rand`, `ammonia` and others), unseen until now because the docs toolchain was outside the existing `audit` job. The latest 0.4.x (0.4.52) still reported 8. The site now builds with mdBook **0.5.4**, verified to produce the same site, with the version selector working and no external assets. 0.5.4 has one remaining advisory, RUSTSEC-2026-0204 (`crossbeam-epoch`, reached via `mdbook → ignore → crossbeam-deque`; the flaw is confined to the `fmt::Pointer` impl of `Atomic`/`Shared`, which neither crate invokes). It is recorded as a time-boxed exception in `MDBOOK_AUDIT_IGNORES` with an owner and an expiry.
| rustdoc (`cargo doc`) | API reference merged under `/api/` | Rust toolchain | `@stable` (floating) | `1.81.0`, same as `rust-toolchain.toml` |
| GitHub Actions | `checkout`, `cache`, `upload/download-artifact`, `rust-toolchain`, `rust-cache`, `install-action`, `typos`, `lychee-action`, `sticky-pull-request-comment` | GitHub Marketplace | Tags (`@v4`, `@v2`, `@stable`) | Full commit SHAs with version comments; Renovate bumps digests monthly (`renovate.json`) |
| Hosting | GitHub Pages from the `gh-pages` branch | `deploy` job pushes with `GITHUB_TOKEN` | Workflow-wide `contents: write` + `pull-requests: write` | Read-only by default; write scopes only on `deploy` / `preview-comment` |

External resources at runtime: none. mdBook's default theme references a CDN
MathJax script and Google Analytics only when `mathjax-support` or
`google-analytics` is configured; `build.py` enables neither, and `seal`
fails the build if any page loads an external script or stylesheet without
Subresource Integrity.

## Threats and mitigations

| # | Threat (same classes as the contract's supply chain) | Mitigation | Enforced by |
|---|---|---|---|
| T1 | **Mutable action tag** re-pointed to malicious code that alters the built site or exfiltrates the token. | All actions pinned to commit SHAs; Renovate updates digests via reviewed PRs. | `supply_chain.py check-pins` (build job) |
| T2 | **Unpinned build tool**: a new mdBook or toolchain release changes output or carries a compromise. | mdBook and Rust pinned exactly; bumping mdBook means changing the version and the crates.io checksum together. | `check-pins` (mdBook pin), workflow `toolchain: 1.81.0` |
| T3 | **Vulnerable transitive dependency** in the generator, unreviewed because it is not in the workspace `Cargo.lock`. | `cargo audit` against mdBook's own `Cargo.lock`, fetched from crates.io and checked against the pinned checksum, on every docs PR and weekly. | `toolchain-audit` job |
| T4 | **Docs tooling pulls in an unvetted package** (e.g. a Python dependency). | Docs tooling is restricted to the Python standard library. | `check-pins` (import scan) |
| T5 | **Third-party script injected into pages** (CDN compromise, theme edit). | No external assets; any future one must carry an SRI `integrity=` attribute or the build fails. Custom theme JS may not reference external URLs. | `supply_chain.py seal`, `check-pins` |
| T6 | **Compromised publishing credential / over-scoped token**: a build-time dependency uses `GITHUB_TOKEN` to rewrite `gh-pages` or PR comments. | Workflow default `contents: read`; `build` and `toolchain-audit` check out with `persist-credentials: false`; only `deploy` (`contents: write`) and `preview-comment` (`pull-requests: write`) hold write scopes, and neither runs mdBook, cargo or any marketplace build action. | Workflow `permissions:` blocks |
| T7 | **Tampering between build and publish**, or with the served site afterwards. | `seal` writes `integrity.json` (SHA-256 of every file and a root digest) into the site; `deploy` re-verifies the artifact against the digest from `build` before and after copying into `gh-pages`; the root digest is published in the Actions run summary, the `gh-pages` commit message and the PR preview comment, all separate from Pages. | `supply_chain.py verify` in `deploy` |
| T8 | **Fork PR abuse** of the deploy path. | Deploy and preview comments run only for same-repository PRs (unchanged). | Job `if:` conditions |

### Residual risk

- `integrity.json` is served from the same origin it describes, so it detects
  tampering only when the reader compares against the out-of-band root digest
  (run summary, `gh-pages` commit, PR comment). It does not stop an attacker
  who controls both the repository and GitHub Pages. Integrators should still
  confirm contract addresses against `deploy/manifests/` at a tagged commit.
- `taiki-e/install-action` downloads the prebuilt mdBook release binary. The
  action verifies its own checksum manifest, but this repository pins the
  crate checksum, not the binary's. Building mdBook from the verified crate
  would close this, at the cost of several minutes per docs build.
- `cargo audit` covers mdBook's Rust graph. The bundled theme's JavaScript
  (highlight.js, elasticlunr, clipboard.js) is vendored inside the mdBook
  release and is covered only by pinning that release.

## Verifying the published site

```bash
# Mirror the version you rely on, then check it against the root digest from
# the docs workflow run summary (or the gh-pages commit message).
wget --mirror --no-parent --no-host-directories --cut-dirs=1 -P site \
  https://ledger-lenz.github.io/Ledgerlens-contract/latest/
python3 tools/docs-site/supply_chain.py verify site/latest --digest <root digest>
```

`verify` reports every missing, modified or unexpected file and fails on any
mismatch.

## Keeping it current

- Renovate's `github-actions` group (monthly, `pinDigests: true`) keeps the
  action SHAs fresh through reviewed PRs.
- Bumping mdBook: update `MDBOOK_VERSION` and `MDBOOK_CRATE_SHA256` in
  `tools/docs-site/supply_chain.py` and the `mdbook@` pin in `docs.yml` in one
  PR. `check-pins` fails if they disagree, and `toolchain-audit` scans the new
  lockfile.
- An advisory in mdBook's graph is handled like a contract advisory
  ([dependency-update-policy.md § Advisory exception expiry](../dependency-update-policy.md#advisory-exception-expiry)):
  upgrade mdBook, or add a time-boxed entry to `MDBOOK_AUDIT_IGNORES` with a reason, an owner and an
  expiry; `audit-ignores` fails the job once an entry expires.
