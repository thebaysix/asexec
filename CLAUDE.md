# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`asexec` ("AsExecuted") is a **primitive, not a platform**: a signing/verification library + a thin CLI for pre-registering AI evals and sealing tamper-evident receipts, so that *silence after a public commitment becomes visible evidence of non-disclosure*. It is the "as executed" counterpart to pre-registration ("as predicted").

Read [`NORTH_STAR.md`](./NORTH_STAR.md) **before proposing any scope expansion.** It is the explicit scope guardrail: no hosted service, no CA, no leaderboard, no adoption/growth workstream. The tool must never claim to prove more than it does — the distinction between `fulfilled` / `open` / `elapsed-no-receipt` / `notarization-only` states, and the "does NOT prove" non-claims, are load-bearing and must stay visible.

## Commands

```bash
# Set up (editable install with dev + optional extras)
python -m pip install -e ".[dev]"

# Run the full test suite (fully offline — the drand round is a baked fixture)
python -m pytest -q

# Run one test file / one test
python -m pytest tests/test_verifier.py -q
python -m pytest tests/test_verifier.py::test_name -q

# CLI is installed as `asexec` (entry point asexec.cli:main); or run as a module:
python -m asexec --version
```

CI (`.github/workflows/ci.yml`) runs pytest + a CLI smoke test on Python 3.9 / 3.11 / 3.12. `requires-python = ">=3.9"`, so avoid 3.10+-only syntax.

## Architecture

The verifier is the product. Signing is the smaller half; the value is that **anyone can verify offline from the spec alone, trusting only a keypair and the published files** — never a platform or the tool's author.

Data flow: `preregister` (before a run) → `seal` (a receipt after each run, `--fulfills` the prereg, optionally chained via `--prev`) → `verify` (offline; groups manifests into commitments and renders states). Publish the JSON files to a public git repo — the repo's *witnessed history* is the (social) "ceiling" that gives "pre" its meaning in v1.

### Modules (`src/asexec/`)

- **`canonical.py`** — the one place a signing bug is expensive. We never sign "some JSON"; we sign the **PAE** (Pre-Authentication Encoding, `asexec-PAE/v1` prefix) of a fixed canonical byte serialization (UTF-8, sorted keys, compact separators, `ensure_ascii=False`). Every serialization rule is documented so any third party can reproduce the signing input. Touch with extreme care.
- **`manifest.py`** — builds/signs/loads the manifest envelope (`payloadType` / `payload` / `signature`); only the `payload` body is signed. `_BEDROCK` = the mandatory fields whose absence would break commitment→fulfillment verifiability; everything else (`freshness`, `identity`, `provenance`, `repro_recipe`, `notes`) is optional context. `ref()` = a signature-independent content hash of the body, used for `fulfills` / `prev_hash` links.
- **`verifier.py`** — two tiers (cryptographic, always offline; content, needs `--artifacts`) and four commitment states. Holds `NON_CLAIMS` (the "does NOT prove" list printed by `verify`). Chain integrity (`_check_chain`) enforces exactly one root and no gaps in a `prev_hash` chain.
- **`keys.py`** — ed25519 via PyNaCl. Pseudonymous, self-managed, **no CA**. `keyid` = `sha-256:<hex of sha256(pubkey)>`. Secret files written mode 0600 with a sibling `.pub`.
- **`drand.py`** — optional (default-on) freshness anchor. Embedding a drand round proves a manifest was created *no earlier than* a public moment (a **freshness floor** — NOT anti-backdating). Verification is fully offline: quicknet chain params (`CHAINS`) are **pinned constants**, never fetched at verify time; only `fetch_round` (sign time) touches the network. BLS12-381 verification via `py_ecc`.
- **`hashing.py`** — content hashing + the `subject` builder. `hash_alg` is a mandatory manifest field so the format is algorithm-agile (sha-256 default/always-available; blake3 optional). Directory hashing = a sorted manifest of per-file hashes (captures contents + relative paths only — documented v1 limitation, not exec bit / symlinks / empty dirs).
- **`identity.py`** — the *one* v1 identity mechanism, and deliberately just a hook: `.well-known/asexec.json` self-assertion (domain owner asserts which keys speak for it). Point-in-time only. The manifest `identity` slot is an open assertion list so richer schemes can be added without a core change.
- **`cli.py`** — argparse; commands `keygen` · `preregister` · `seal` · `verify` · `identity`. Files-first: `--commit` does `git add`+`commit` only, **never push**. `verify` is fully offline; only sign-time drand fetch and `identity verify` touch the network.

### Design boundaries to preserve

- **`verify` is offline. Keep it that way.** Anything requiring the network at verify time is a design smell — pin it as a constant (as with drand chain params) instead.
- **Non-claims are a feature.** When changing what the tool checks, update `NON_CLAIMS` in `verifier.py` and the README's "what it does NOT prove" section together. Never let the output imply a stronger guarantee than exists (e.g. the "pre" is *social* in v1, not cryptographic).
- **Mandatory vs. optional fields** is a deliberate trust gradient. Only add to `_BEDROCK` if the field's absence would break commitment→fulfillment verifiability.
- Version string lives in `src/asexec/__init__.py` (`__version__`) and is mirrored in `pyproject.toml`.

## Design record

The full context/blind-spots/brainstorm/interview/plan/notes live in `crystallize/` (00–07, gitignored — local only) and, name-stripped, in **GitHub issue #1** (`lwhitestone/asexec`). This repo is an active *crystallize* effort (see `.crystallize.json`): when implementing against `crystallize/04-plan.md`, log deviations to `crystallize/05-notes.md` under "Decisions & deviations". The version-keyed backlog lives in [`ROADMAP.md`](./ROADMAP.md): the next release (**0.2.0**) is the schema rebalance + drand floor/ceiling + verifier redesign; later releases cover the per-key public index (0.3.0) and re-execution/determinism mode (0.4.0). Re-execution/determinism mode, OpenTimestamps/Bitcoin cryptographic ceiling, hash-log anchoring, and web-of-trust / key transparency are all deferred (the last three explicitly not scheduled).
