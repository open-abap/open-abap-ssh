# Plan: multi-operation SFTP sessions

Goal: remove the one-operation-per-instance restriction for SFTP, so one
authenticated connection with one host-key verification can run many SFTP
operations (list, download, stat, ...) over a single `sftp` subsystem
channel, ending with an explicit close. Command execution and shell keep
their one-shot contract.

Non-goals: concurrent outstanding operations (one SFTP operation at a time
per session), connection reuse across `execute`/`shell`/SFTP kinds, and
reopening a second channel after close.

## Why the restriction exists today

The limit is self-imposed by the orchestration layer, not by the protocol:

- `zcl_oassh` guards every public operation with `mv_operation_started`,
  which is never cleared. One instance = one operation.
- Each `sftp_*` method creates a fresh `mo_sftp` and a fresh channel;
  `advance_channel` sends `CHANNEL_CLOSE` as soon as
  `mo_sftp->get_state( ) = c_state-finished` and the outbound queue is
  empty. The subsystem dies with the operation.
- `start_channel( )` asserts `mo_channel IS NOT BOUND`, so a closed channel
  cannot be replaced within the same instance.

SFTP itself is a request/response protocol over one long-lived channel:
INIT/VERSION once, then independent request ids. Nothing in RFC/draft SFTP
v3 requires reconnecting between operations.

## What already helps

- `zcl_oassh_sftp=>start( )` sends INIT alone (today only used by unit
  tests); the production path couples INIT with the first operation via
  `start_x` from state `created`. The decoupled entry point already exists.
- `mv_next_request_id` lives on the instance and simply keeps counting, so
  request-id uniqueness across operations is free if the same `mo_sftp`
  instance is kept for the whole session.
- The interactive exec work (`exec_open`/`exec_read`/`exec_write`/
  `exec_close`, see docs/interactive-exec.md) established the pattern of an
  operation that returns control to the caller while the channel stays
  open, including the "pump the socket until a condition other than
  operation-done" loop shape.

## Target API (decision)

**Option A (recommended): modal session on `zcl_oassh`.**

```abap
lo_ssh = zcl_oassh=>connect( ... ).
lo_ssh->sftp_open( ).                          " channel + subsystem + INIT/VERSION
lt_names = lo_ssh->sftp_list( '/dir' ).        " same methods as today
lv_data  = lo_ssh->sftp_download( '/dir/a' ).
ls_attrs = lo_ssh->sftp_stat( '/dir/a' ).
lo_ssh->sftp_close( ).                         " channel close handshake
lo_ssh->close( ).
```

`sftp_open( )` switches the instance into session mode
(`gc_operation-sftp_session`); the existing `sftp_*` methods detect the open
session and run inside it instead of raising the second-operation error.
Without `sftp_open( )` they behave exactly as today (one-shot, connection
per operation) — no caller breaks.

Option B (separate `zcl_oassh_sftp_client` facade holding the connection)
was considered and rejected: it duplicates the public SFTP surface, and the
exec precedent already put interactive operations directly on `zcl_oassh`.

## Work breakdown

### M1 — reusable operation lifecycle in `zcl_oassh_sftp`

Smallest-churn approach: keep the existing state machine, including the
terminal `c_state-finished`, and add

- `continue_session( )`: allowed only in `finished`; clears the per-op
  result state (`mt_data`, `ms_attrs`, `mt_names`, `ms_realpath`,
  `mv_error_status`, `mv_last_response_*`, handle/offset fields) and
  returns the state to `ready`. Request ids keep counting.
- Guard every `start_x` so it is callable from `ready` (post-VERSION) as
  well as the current `created` (combined INIT) path.

One-shot flow in `zcl_oassh` is untouched — it still checks `finished`.
Unit tests: multi-op sequences against the pure state machine with wire
fixtures (list → download → stat on one instance; status error → close →
`continue_session` → next op; request ids strictly increasing). This layer
needs no SSH transport, so it carries most of the test weight.

### M2 — session plumbing in `zcl_oassh`

- New `gc_operation-sftp_session`.
- `sftp_open( iv_timeout_seconds )`: guard `mv_operation_started`, create
  `mo_sftp`, start channel when authenticated, drive the socket (exec_open
  loop shape) until `mo_sftp` reaches `ready` (VERSION received). In
  `advance_channel`, the session case sends `mo_sftp->start( )` when the
  channel starts running, and never auto-closes the channel.
- Per-op execution inside the session: each `sftp_*` method branches at the
  top — if a session is open, call the matching `start_x` from `ready`,
  then pump until `finished`, harvest the result, check
  `get_error_status( )` (raise e012 with the SFTP status as today), call
  `continue_session( )`, return. Timeout applies per call.
- `sftp_close( iv_timeout_seconds )`: send `CHANNEL_CLOSE`, pump until the
  peer's close (exec_close shape). `close( )` on the socket stays separate.
- Session validity rule: a clean completion **including SFTP status
  errors** leaves the session usable (the protocol class already closes
  remote handles on status errors before finishing). A timeout or any
  transport/protocol error mid-operation leaves the session in an undefined
  protocol position — mark the session broken; subsequent `sftp_*` calls
  raise e010, only `close( )` remains.

### M3 — regression safety for the one-shot paths

No behavior change intended. Acceptance: all existing recorded-session
fixtures stay byte-exact green (`recorded_session`, `sftp_*_recorded_*`),
plus the existing SFTP unit tests in `zcl_oassh_sftp.clas.testclasses.abap`
(updated only where M1 adds cases, not where semantics are asserted).

### M4 — session-level tests

- FRIENDS-driven unit test on `zcl_oassh` for the guards and the
  session-mode dispatch (mirrors `exec_stream_session`): open-state checks,
  broken-session behavior, close handling. The encrypted send path cannot
  be exercised this way (needs derived keys) — same limitation as exec.
- Integration script `integration/sftp-session.mjs` against the pinned
  OpenSSH container: one connection, list + download + stat + rename on the
  existing fixtures. Record its inbound/outbound and embed it as an
  `sftp_session_recorded_session` unit test like the existing recordings.
  (Remember the local-container harness notes: run paths through `sh -c`
  on Git Bash; keep timeouts above the slow RSA verify.)

### M5 — docs and examples

- README: SFTP section gains the session variant and drops the "open a
  fresh connection for each operation" wording for SFTP (it stays true for
  execute/shell); note the performance benefit given the 1-byte APC frame
  cost of every handshake.
- `docs/sftp-sessions.md`: API, per-call timeouts, session-validity rules.
- `examples/zoassh_example_sftp.prog.abap`: switch to one connection with
  `sftp_open`/`sftp_close` — this directly answers "why does the example
  connect twice".

## Risks / notes

- **Recorded-fixture drift** is the main regression risk; M3 pins it.
- **Rekey mid-session** is already transparent (`process_encrypted` handles
  server-initiated KEXINIT in the encrypted state) and long sessions make
  it more likely; the integration scenario should force one rekey
  (`RekeyLimit` on the container) to prove it.
- **Window replenishment** across many downloads is already handled by
  `consume_local_window`; no change expected.
- **Request-id wrap** is theoretical (int4, one id per request); document
  as out of scope.
- Effort centers on M1+M2; M4's recording is mechanical once the container
  scenario runs.
