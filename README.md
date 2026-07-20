# asexec — AsExecuted

> Part of the work at **[lukewhitest.one](https://lukewhitest.one/)** — AI infrastructure & risk stewardship.

**Pre-registered trials for AI evals.** A local-first, pseudonymous, offline-verifiable
cryptographic primitive: an evaluator commits to running an eval *before* the results are
known, then publishes tamper-evident, independently-verifiable receipts of what actually
happened — so that **silence, after a public commitment, becomes visible evidence of
non-disclosure.**

It is the "as executed" counterpart to pre-registration ("as predicted"), borrowing the
commit-then-reveal mechanism from clinical-trial pre-registration and applying it to the
selective-disclosure problem in AI safety evaluations.

> **A primitive, not a platform.** A signing/verification library + thin CLI. No hosted
> service, no CA, no leaderboard. Publish the files wherever you like (a public git repo is
> the intended home).

---

## What this does — and, plainly, what it does NOT prove

**It proves:**
- A manifest (pre-registration or receipt) was not altered after signing.
- A receipt references a specific prior pre-registration, and a receipt sequence wasn't
  silently truncated/reordered (a `prev_hash` chain).
- Whether a declared disclosure window has elapsed and whether matching receipts exist —
  rendered as an explicit state (`fulfilled` / `open` / `elapsed-no-receipt` /
  `notarization-only`).
- (Optional drand anchor) that a manifest was created no earlier than a public moment —
  **freshness**, not backdating-resistance.

**It does NOT prove** (surfaced in `verify` output, not just here):
- **Identity.** Keys are pseudonymous. Binding a key to a real entity is a separate,
  optional `.well-known` check — asexec is not a CA.
- **That the pre-registration truly preceded the run ("pre") — cryptographically.** In v1
  the "pre" is *social*: it rests on the pre-registration being published to a **watched
  public repo** before the run, not on a cryptographic ceiling. (A future `--ots` mode adds
  an OpenTimestamps/Bitcoin ceiling for proof to a non-observer.)
- **Provenance.** Content hashes prove a transcript wasn't *altered*; they do **not** prove
  it is the output of the named harness+model (asserted by the signer, not re-executed).
- **Completeness.** It renders only the manifests you give it; it cannot prove a lab
  pre-registered every eval it should have (selective pre-registration).
- **Eval quality / elicitation rigor / sandbagging.** Entirely out of scope — this makes the
  *process* auditable, not the science.

---

## Install

```bash
pip install asexec          # ed25519 (PyNaCl) + BLS verification for drand (py_ecc)
```

Python ≥ 3.9. `verify` is fully offline; only the sign-time drand fetch and
`identity verify` touch the network.

## Quickstart (the full commit-then-reveal cycle)

```bash
# 1. one-time: generate a pseudonymous keypair (no CA, no registration)
asexec keygen --out lab.key

# 2. BEFORE the run: pre-register the harness + a disclosure deadline
asexec preregister --key lab.key \
    --subject ./harness \
    --target-provider anthropic --target-model claude-opus-4-8 \
    --window 2026-08-30T00:00:00Z \
    --declares "all runs of this harness against this model, in full" \
    --out preregistration.json --commit

# 3. AFTER each run: seal a receipt of the inputs + transcript
asexec seal --key lab.key --fulfills preregistration.json \
    --subject ./transcript.txt ./harness \
    --out receipt.json --commit

# 4. ANYONE, offline: verify the cycle + render the commitment state
asexec verify preregistration.json receipt.json --artifacts .
```

Publish `preregistration.json` and `receipt.json` to a public repo. A third party clones it
and runs step 4 with no network and no involvement from you.

## Identity (optional, no CA)

```bash
# a domain owner asserts which keys speak for it:
asexec identity emit --key lab.key --domain lab.example --out asexec.json
#   -> publish at https://lab.example/.well-known/asexec.json

# anyone checks the binding (point-in-time; a domain can rotate keys):
asexec identity verify --domain lab.example --key lab.key
```

## Manifest at a glance

Bespoke signed JSON, signed over a DSSE-style PAE input (borrows in-toto field names, not the
tooling). **Mandatory** fields are exactly those whose absence would break verifiability of
*commitment → fulfillment/gap*: `disclosure_window`, `target_identity`, `hash_alg` (+ signing
plumbing). Everything else — `freshness` (drand, default-on), `identity`, `provenance` +
`repro_recipe`, free-form `notes` — is optional context; specificity is a trust gradient the
reader prices.

## Design & rationale

The full design record (context, blind-spots, brainstorm, interview, plan) lives in the
[v1 implementation plan, issue #1](https://github.com/thebaysix/asexec/issues/1). Prior art:
AsPredicted / OSF pre-registration, ClinicalTrials.gov + the FDAAA TrialsTracker,
OpenTimestamps, in-toto / DSSE, drand / League of Entropy.

**Scope & philosophy:** [`NORTH_STAR.md`](./NORTH_STAR.md) — what this project is for, and
(deliberately) what it is *not* chasing. Read it before proposing scope expansions: this is a
primitive dogfooded honestly at small scale, not a platform or an adoption play.

## Status

v0.1 — alpha. See issue #1 for the staged roadmap and the named v2 items (OTS/Bitcoin
cryptographic ceiling, re-execution/determinism mode, hash-log anchoring, web-of-trust / key
transparency).

## License

Apache-2.0.
