# AGENTS.md

This file applies to the entire repository. It is the working agreement for
agents changing `open-abap-ssh`.

## Mission and source of truth

Build a correct, interoperable SSH-2 client in portable ABAP. It must run both
on SAP systems and, through abaplint/open-abap, on Node.js.

Before changing code, read:

1. `scribblings/PROMPT.md` for the autonomous work loop.
2. `scribblings/CHECKLIST.md` for the next open deliverable.
3. `scribblings/PLAN.md` for architecture, milestones, and definition of done.
4. `scribblings/ANORMALIES.md` for known SAP/transpiler differences.

Work on the first feasible unchecked item unless the user gives a more specific
priority. Keep the checklist and plan honest: mark an item complete only after
its implementation, review, and applicable tests pass. Record newly discovered
abaplint, transpiler, open-abap, or SAP-runtime differences in
`scribblings/ANORMALIES.md`, including a minimal reproduction and workaround.

Do not claim the actual-ECC demo is complete without access to and a successful
run on an actual ECC system. NPL is an on-premise compatibility proof, but it is
not the missing ECC target.

## Repository boundaries

- `src/` contains production ABAP, ABAP Unit test includes, and abapGit XML.
- `integration/` contains live OpenSSH drivers for transpiled ABAP.
- `scripts/` contains dependency checks and narrowly scoped runtime adapters.
- `.github/workflows/test.yml` is the live interoperability matrix.
- `output/` is generated. Never edit or commit it.

Production protocol code must not depend on Node.js or test-only facilities.
Keep platform behavior behind `zif_oassh_socket`, `zif_oassh_random`, host-key
verification, and their adapters. Preserve the dependency rules enforced by
`npm run test:dependencies`. A runtime patch is acceptable only when it adapts
an unavailable platform primitive; document and test it rather than hiding
protocol behavior in JavaScript.

Use the established `zcl_oassh_*`, `zif_oassh_*`, and `zcx_oassh_*` naming.
Keep every class's `*.clas.abap`, `*.clas.testclasses.abap`, and `*.clas.xml`
artifacts consistent. Prefer small protocol-layer methods and explicit state
transitions over large nested callback branches.

## Research and protocol correctness

SSH and cryptography changes require primary sources. Start with the relevant
IETF RFCs, official SAP documentation or SAP Notes for ABAP/platform behavior,
and upstream OpenSSH source or protocol documents for OpenSSH extensions. Use
secondary web material only for orientation, never as the normative basis for
wire formats or security decisions. Cite the governing section in code comments
where an encoding, validation rule, state transition, or construction is not
obvious.

For every wire or cryptographic change:

- Compare the exact byte layout, length prefixes, integer representation,
  negotiation order, and state transition with the specification.
- Reject non-canonical, malformed, out-of-range, unauthenticated, or oversized
  input before it reaches stateful processing.
- Authenticate ciphertext before exposing plaintext.
- Preserve SSH packet sequence-number and rekey semantics.
- Treat host-key verification as mandatory. Never weaken it to make a test pass.
- Use official vectors plus negative and boundary tests. For crypto, add
  independent variance tests against a trusted implementation where practical.
- Pin external test images and fixtures so upstream changes cannot silently
  redefine expected behavior.

Correctness comes before micro-optimization. Optimize only with equivalent
tests in place, and be especially careful with ABAP signed arithmetic, byte
types, `xstring` slicing/concatenation, leading zeroes, and integer overflow.
Do not describe the pure-ABAP crypto as constant-time unless that property has
been demonstrated.

## Portable ABAP rules

The supported compatibility floor includes NPL SAP_BASIS 750. Code that passes
abaplint or transpiles is not automatically valid ABAP.

- Avoid syntax unavailable on 7.50, including `RAISE EXCEPTION NEW` in this
  codebase; use the established exception helper pattern.
- Use fully typed returning parameters. Do not return generic `x`.
- Assign `xstring` slices to a typed temporary before passing them to methods.
- Do not rely on direct `x` ordering or arithmetic; convert bytes to integers
  explicitly when unsigned behavior matters.
- Avoid method calls in `WAIT UNTIL`, and account for open-abap's timeout and
  boolean representation differences.
- Keep loops that contain early `RETURN` simple and isolated because of the
  transpiler loop-index scoping issue documented in `ANORMALIES.md`.
- At handwritten JavaScript boundaries, normalize `XString` hexadecimal text to
  uppercase.
- Do not use character operations for binary data.

When SAP and transpiled behavior disagree, preserve standards-correct behavior
on both runtimes if possible. Add a regression test on each affected runtime and
document the discrepancy; do not silently specialize production logic for the
test harness.

## Required validation

Use the narrowest useful test while iterating, then widen the gate. A completed
code item normally requires all applicable tiers:

1. **Tier 1 — local static and unit tests**
   - Add colocated ABAP Unit tests for happy paths, exact wire output, malformed
     input, boundaries, and state errors.
   - Run `npm run test:dependencies` after dependency changes.
   - Run `npx abaplint` while iterating.
   - Run `npm test` before committing a completed item.
2. **Tier 2 — deterministic session replay**
   - For transport/authentication/channel changes, replay the recorded OpenSSH
     stream through the mock socket and fixed RNG.
   - Verify the complete inbound fixture is consumed and the complete outbound
     byte stream matches. Update fixtures only when a reviewed protocol change
     necessarily changes them; explain the byte-level reason.
3. **Tier 3 — live OpenSSH interoperability**
   - Exercise the transpiled client against the pinned Docker OpenSSH image.
   - Force the algorithm or mode under test so a fallback cannot create a false
     pass.
   - Assert negotiation and application-level output, not just process exit.
   - Add or update CI coverage for durable modes and algorithms.

Also validate changed ABAP sources on both configured SAP systems:

- **A4H**: activate, syntax-check, run focused and relevant full ABAP Unit tests,
  run deterministic replay, and run ATC for the changed scope.
- **NPL SAP_BASIS 750**: deploy without Eclipse through the configured ARC-1/ADT
  tooling, activate dependencies in stages when necessary, syntax-check, and run
  focused plus relevant full ABAP Unit/replay tests.

Use only the A4H and NPL systems configured in the local ARC-1
`infrastructure.md`/`.env.infrastructure`. **Do not use DER.** Never copy system
URLs, users, passwords, tokens, private keys, or the infrastructure file into
the repository, patches, logs, commits, PR text, or chat output. Pass credentials
through environment variables and avoid shell tracing. NPL is writable through
the configured tooling; Eclipse is not required.

A live SAP/APC test is required only when the changed path uses the APC adapter
and the target is reachable. If infrastructure blocks a test, exhaust safe
read-only diagnostics, preserve the exact technical evidence, and report the
test as blocked rather than passed.

## Review and completion loop

For each checklist item:

1. Research the governing specifications and inspect adjacent code/tests.
2. Implement the smallest complete vertical slice.
3. Add tests and run the applicable validation tiers.
4. Review the diff for protocol correctness, security, portability, error
   handling, performance regressions, secret leakage, and scope creep.
5. Fix every actionable finding and rerun affected tests.
6. Update `CHECKLIST.md`, `PLAN.md`, and `ANORMALIES.md` only when the evidence
   supports the update.
7. Make a focused, sensible commit.

After all feasible plan items are complete, perform a fresh whole-PR review from
the merge base, not merely a review of the last commit. Run the full local suite,
all applicable live integrations, A4H/NPL validation, and inspect CI. Resolve
actionable anomalies and repeat the affected review/tests before declaring the
PR ready.

## Git and PR discipline

The worktree may contain user or unfinished agent changes. Always inspect
`git status`, the staged diff, and the unstaged diff. Preserve unrelated changes
and stage explicit paths; never use `git add -A` in a mixed worktree. Do not use
destructive reset/checkout commands.

Make commits cohesive and terse. Do not combine documentation, fixture churn,
and unrelated behavior changes unless they form one reviewed deliverable. Before
each commit, run `git diff --check` and inspect the staged patch. Never commit
credentials, generated `output/`, temporary captures, or local infrastructure
configuration.

Push only the intended branch. Before updating the PR, verify its head/base,
review the complete outgoing commit range, and ensure the PR description and
checklist accurately describe validation and remaining external blockers. After
push, monitor required checks and investigate failures from their logs; do not
assume a local pass makes the PR complete.
