# Roadmap

The canonical, version-keyed backlog for `asexec`. Scope is checked against
[`NORTH_STAR.md`](./NORTH_STAR.md) — read it before proposing anything that
expands the surface. The [design record (issue #1)](https://github.com/lwhitestone/asexec/issues/1)
holds the deeper rationale.

**Ordering logic:** cheap-and-sharp gaps first; items that form one coherent
release ship together; completeness/adoption-adjacent work sits behind core
correctness; anything needing outside cooperation or heavy new infra is pushed
to the back since it's lowest-control.

## Versioning

- **Releases** use `0.MINOR.PATCH`, pre-1.0 alpha. A `MINOR` bump is a
  meaningful format or verifier-output change; a `PATCH` is additive/small.
- **Format version tags are a separate, frozen namespace — not roadmap
  versions.** `SCHEMA_VERSION` (`asexec/v1`), the PAE prefix
  (`asexec-PAE/v1`), and the predicate type (`.../manifest/v1`) are baked into
  signed bytes; renumbering them would change the signing input and break
  verification. Whether a schema change (e.g. the 0.2.0 rebalance) bumps the
  schema tag is decided per-change on backward-compatibility grounds,
  independent of the release number.
- **`1.0.0` is deliberately unassigned.** No trigger is defined yet — it is not
  tied to dogfooding, team usage, or any other indicator. Leave it open until
  there's a concrete reason to fix it.

## Version map

| Version | Status | Theme | Backlog items |
|---|---|---|---|
| **0.1.0** | shipped (alpha) | Core primitive: keygen · preregister · seal · verify · identity; offline verifier; drand freshness | — |
| **0.2.0** | next | Schema rebalance + freshness anchors + verifier redesign | #1–#6 (ship together) |
| **0.3.0** | planned | Completeness: per-key public index convention | #10 |
| **0.4.0** | planned | Re-execution / determinism mode | #12 |
| *unversioned* | opportunistic | Multi-party co-signing · regulatory cross-reference field | #13, #14 |
| *unversioned* | process (not a release) | Dogfooding · land design docs · team/customer usage | #7, #8, #9 |
| *separate repo* | not core `asexec` | Verification website | #11 |
| — | explicitly not scheduled | Third-party witness services · hosted transparency log · identity binding / CA | — |

---

## 0.2.0 — schema rebalance, freshness anchors, verifier redesign  *(next release)*

Items #1–#6 are one coherent release and ship together: #1 defines the field
taxonomy, #2–#5 populate it, and #6 is the verifier that reads all of it. The
mandatory-set change and the new verifier output are what make this a `MINOR`
bump.

1. **Schema rebalance: bedrock vs. recommended-optional vs. free-form**
   - Confirm/enforce only `disclosure_window` and target/`model_identity` as
     mandatory (bedrock) — verifiability of the central
     commitment→fulfillment claim breaks without these.
   - Everything else (Q1-equivalent, drand floor, drand ceiling,
     sequence/supersedes, free-text) becomes fully optional, individually.
   - Publish a documented "recommended bundle" (not enforced) consisting of:
     Q1-equivalent, drand floor, drand ceiling.

2. **Q1-equivalent field** — `has_run_already` (binary + "it's complicated"
   escape hatch, mirroring AsPredicted Q1) at `preregister` time. Pure schema
   addition, no new crypto.

3. **Drand floor** — reference a drand round at/before manifest creation time in
   `preregister`; proves creation **at or after** that round. Ships as part of
   the recommended bundle, not bedrock.

4. **Drand ceiling** — a second, later drand round reference (or equivalent
   anchor-after-creation mechanism) proving creation **no later than** that
   round. Requires waiting for a subsequent round to exist before it can be
   attached — document this latency explicitly (fast, ~3s cadence, but not
   instant).
   - Manifest schema should use two distinct fields (e.g., `floor_round`,
     `ceiling_round`), not one ambiguous field — floor and ceiling are
     structurally different proofs and must stay distinguishable.

5. **Anchor field made extensible, not hardcoded to drand** — `anchor_type`
   supports `drand | nist | ots | none` (or similar), room to add more later.
   Drand ships as the documented default; nothing in the schema privileges it
   structurally over future alternatives.

6. **Verifier redesign: point-by-point tests → canonical plaintext code output**
   - Bedrock tests always run unconditionally on every `verify` call.
   - Optional tests (Q1, floor, ceiling, sequence, others as added) run only if
     requested via verify-call options — never run-by-default against fields the
     evaluator never attempted.
   - Output is a canonical code: sorted (alphabetical) list of test IDs actually
     run, each pass/fail, not a percentage or tier. Tests not mentioned in the
     code were not run — never implied as failed.
   - Canonical serialization spec'd precisely (test ID naming, alphabetical
     ordering, delimiter, per-test vs. aggregate marker) so two runs of the same
     test set always produce byte-identical codes.
   - Explicit, prominent disclaimer co-located with every code output: the code
     is a summary of a reproducible computation, not a certificate — a
     quoted/typed code proves nothing on its own; only re-running the tool
     against the manifest and artifacts constitutes verification.
   - Default CLI invocation (no flags) runs bedrock + full recommended bundle,
     not bedrock-only — the lazy path should be strict, not permissive.
     Bedrock-only or custom subsets are an explicit opt-*down*.

## 0.3.0 — per-key public index convention

10. **Per-key public index convention** (`.well-known/asexec-index.json` or
    similar) — addresses the completeness/selective-non-registration gap (the
    highest-leverage remaining hole per the market-for-lemons argument).
    Convention-only, no hosting required.

## 0.4.0 — re-execution / determinism mode

12. **Re-execution/determinism mode** — needs to degrade gracefully for
    legitimately non-deterministic evals or it will cry wolf. Wait for real
    transcripts from dogfooding (#7) to calibrate against.

## Opportunistic (unversioned until scheduled)

These are real features that would land as a `MINOR`/`PATCH` bump when a
concrete need appears; not on a timeline.

13. **Multi-party co-signing** (optional second signer at pre-registration) —
    cheap to spec, low urgency until requested.

14. **Structured regulatory cross-reference field** (e.g., SB-53/RAISE-Act
    filing ID) — adoption hook more than technical gap; add opportunistically if
    a real compliance use case appears.

## Process milestones (not tied to a release)

These gate the release work but are not themselves versioned artifacts.

7. **Dogfooding: run your own evals through the full cycle**, using the
   rebalanced schema (0.2.0) and new verifier output. Gates everything after it
   — surfaces rough edges no design discussion catches (messy harnesses,
   non-determinism, disclosure-window UX, whether the recommended bundle is
   actually usable in practice).

8. **Land `NORTH_STAR.md` and the design-rationale doc in the repo** — commit
   before wider external visibility so early readers get honest scope up front.
   (`NORTH_STAR.md` and this `ROADMAP.md` are in-repo; the deeper rationale
   lives in issue #1.)

9. **Team/customer-facing usage** — first test of the social-contract thesis
   under real, if modest, stakes. Depends on dogfooding (#7) going reasonably
   smoothly.

## Separate deliverable (not core `asexec`)

11. **Verification website** — explicitly *not* core `asexec`; its own
    repo/deliverable with its own versioning. Lowers the barrier for
    non-technical reviewers. Designed so anyone could build a competing instance
    from the open manifest + code spec alone — not owned long-term by the core
    project.

## Explicitly not scheduled

Third-party witness services, hosted transparency log, identity binding / CA.
All reintroduce trust/infra layers the project was built to avoid (see
[`NORTH_STAR.md`](./NORTH_STAR.md)). Revisit only if a specific, concrete need
forces the question — not on a timeline.
