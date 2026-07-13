# open-abap-ssh — Checklist 2: SFTP subsystem

Delivers the open M9 item "sftp subsystem" from `CHECKLIST.md`. Work the
milestones in order; each is a complete vertical slice with its own tests.
The rules in `AGENTS.md` (validation tiers, portability, naming) apply to
every item here.

## Normative sources

- SFTP protocol **version 3**: draft-ietf-secsh-filexfer-02. This is what
  OpenSSH `sftp-server` implements; later drafts (v4–v6) are NOT the target.
  Do not take wire formats from later drafts — v3 differs (e.g. ATTRS layout,
  no text encodings).
- Channel plumbing: RFC 4254 §6.5 (`subsystem` channel request), §5.2 (data
  transfer, window).
- OpenSSH behavior/limits: upstream `sftp-server.c` / `PROTOCOL` file
  (e.g. extensions announced in VERSION, max read/write sizes).

## Architecture (decide before coding)

- **New class `zcl_oassh_sftp`** — the SFTP client state machine. It consumes
  raw bytes that arrived as CHANNEL_DATA and produces SFTP request packets to
  be sent as CHANNEL_DATA. It must not know about SSH packets, sockets, or
  the transport; mirror how `zcl_oassh_channel` is layered.
- **`zcl_oassh_channel` stays generic**: add a `subsystem( iv_name )` method
  next to `exec` (RFC 4254 §6.5, same `SSH_MSG_CHANNEL_REQUEST` shape with
  request type `subsystem`), and a way for the owner to obtain inbound
  CHANNEL_DATA incrementally instead of only via `get_stdout( )` at close.
  Reuse the existing window-management/replenishment path unchanged.
- **`zcl_oassh` drives the operation**: today `execute( )` stores
  `mv_command` and socket callbacks drive the channel until closed
  (`process_encrypted`). SFTP follows the same pattern: a public method sets
  up an operation plan, `mi_socket->wait( )` yields, and the callback loop
  advances the SFTP state machine on every CHANNEL_DATA. Generalize the
  single `mv_command`/`mv_command_done` pair into an operation concept rather
  than duplicating the flow.
- **Framing is independent of CHANNEL_DATA boundaries.** One SFTP packet may
  span several CHANNEL_DATA messages, and one CHANNEL_DATA may contain
  several SFTP packets. `zcl_oassh_sftp` needs its own reassembly buffer
  (reuse `zcl_oassh_stream` chunk tables; do not concatenate per byte).

## Wire format cheat sheet (v3)

Every SFTP packet: `uint32 length` (excludes itself) + `byte type` + body.
All requests after INIT carry a client-chosen `uint32 request-id` which the
response echoes. Validate the echoed id strictly; an unknown id is a protocol
error, not something to skip.

Requests: `SSH_FXP_INIT` 1, `OPEN` 3, `CLOSE` 4, `READ` 5, `WRITE` 6,
`LSTAT` 7, `FSTAT` 8, `OPENDIR` 11, `READDIR` 12, `REMOVE` 13, `MKDIR` 14,
`RMDIR` 15, `REALPATH` 16, `STAT` 17, `RENAME` 18.
Responses: `VERSION` 2, `STATUS` 101, `HANDLE` 102, `DATA` 103, `NAME` 104,
`ATTRS` 105.
STATUS codes: `SSH_FX_OK` 0, `EOF` 1, `NO_SUCH_FILE` 2, `PERMISSION_DENIED` 3,
`FAILURE` 4, `BAD_MESSAGE` 5, `OP_UNSUPPORTED` 8.
OPEN pflags: `READ` 0x01, `WRITE` 0x02, `APPEND` 0x04, `CREAT` 0x08,
`TRUNC` 0x10, `EXCL` 0x20.
ATTRS: `uint32 flags`, then only the fields whose flag bit is set
(`SIZE` 0x1 → uint64, `UIDGID` 0x2 → 2×uint32, `PERMISSIONS` 0x4 → uint32,
`ACMODTIME` 0x8 → 2×uint32, `EXTENDED` 0x80000000 → count + pairs). Parse it
exactly; a truncated ATTRS must raise, not default.

READ/WRITE file offsets are **uint64**. Confirm each byte layout against the
draft before implementing; the list above is orientation, not the spec.

## S0 — Groundwork

- [x] `zcl_oassh_stream`: `uint64_encode`/`uint64_decode`. ABAP has no
      unsigned 64-bit type and `int8` may behave differently under the
      transpiler — represent the value as `x LENGTH 8` (or two uint32 halves)
      internally, and cap accepted sizes/offsets at a documented int4-safe
      ceiling (2 GiB is far beyond realistic APC use). Tests: zero, small,
      0x00000000FFFFFFFF boundary, high-half rejection, truncation.
      Implemented as two 4-byte halves; the high half must be zero and the low
      word must have its top bit clear (`<= 0x7FFFFFFF`), both enforced on
      decode. Seven tier-1 tests (zero, small, max int4, low boundary,
      high-half, truncation, negative-encode).
- [x] `zcl_oassh_channel=>subsystem( iv_name )` — same shape as `exec`
      (`want_reply` true, wait for CHANNEL_SUCCESS/FAILURE); either reuse the
      `exec_sent` state or add a dedicated one, but keep the state machine
      explicit. Test: exact wire bytes for `subsystem "sftp"`, and
      CHANNEL_FAILURE surfaces a typed error.
      Reuses `exec_sent` (same want_reply/CHANNEL_SUCCESS-FAILURE cycle); the
      name is encoded as an ASCII token. Two tier-1 tests: exact wire bytes for
      `subsystem "sftp"` + running transition, and typed CHANNEL_FAILURE.
- [x] Incremental inbound data hand-off from channel to owner (SFTP must
      react to data while the channel is still open; `get_stdout( )` at
      close is not enough). Keep `execute( )` behavior unchanged — regression
      via existing tier-2 replay.
      `zcl_oassh_channel=>drain_stdout( )` returns the CHANNEL_DATA buffered
      since the previous drain and clears it, so an owner can react per-receive
      and a large transfer never accumulates the whole stream. `execute( )`
      never drains, so `get_stdout( )`-at-close is unchanged (tier-2 replay
      still green). Tier-1 test `drains_incrementally`.

## S1 — SFTP framing + INIT/VERSION

- [ ] `zcl_oassh_sftp`: packet reassembly (length-prefix framing over a chunk
      buffer), request-id allocation, response dispatch. Reject: length < 1,
      length above a documented ceiling (OpenSSH uses 256 KiB — pick and
      assert one), response id mismatch, unknown response type.
- [ ] `SSH_FXP_INIT (version=3)` → parse `VERSION`; require version 3, store
      but ignore extension pairs. INIT/VERSION carry **no** request-id —
      keep that special case isolated.
- [ ] Tests: exact INIT bytes; VERSION with and without extensions; VERSION
      split across two data chunks; two responses in one chunk; garbage type;
      version 6 rejected with a typed error.

## S2 — Download slice ⭐ first shippable

- [ ] State machine: `INIT → VERSION → OPEN(path, SSH_FXF_READ, empty ATTRS)
      → HANDLE → READ loop → SSH_FX_EOF → CLOSE(handle) → STATUS → channel
      close`. Chunked READ at 32768 bytes per request (interop-safe under
      OpenSSH limits); the server may return **less** than requested — advance
      the offset by what actually arrived. `SSH_FXP_DATA` on a short final
      read and `SSH_FX_EOF` are both normal termination paths.
- [ ] Any STATUS other than OK/EOF at the step that expects it → typed
      `zcx_oassh_error` carrying the SFTP status code; still CLOSE the handle
      and the channel on the error path (no leaked handles).
- [ ] Public API on `zcl_oassh`: `sftp_download( iv_path, iv_timeout_seconds )`
      returning `xstring` (binary-safe — no `zcl_oassh_ascii` conversion of
      file content). Same one-operation-per-connection contract as
      `execute( )` for now; assert against mixing the two.
- [ ] Tier 1: full-download happy path against a scripted response sequence;
      short reads; zero-byte file; NO_SUCH_FILE; DATA for a stale request id;
      READ response arriving after EOF.
- [ ] Tier 2: recorded OpenSSH sftp session replayed through mock socket +
      fixed RNG — complete inbound fixture consumed, outbound bytes exact.
- [ ] Tier 3: `integration/sftp.mjs` — Docker OpenSSH with the sftp
      subsystem, download a pinned fixture file, byte-compare. Assert the
      subsystem request succeeded (no exec fallback masking a failure).

## S3 — Upload slice

- [ ] `OPEN(path, WRITE|CREAT|TRUNC, empty ATTRS) → HANDLE → WRITE loop
      (32768-byte chunks, offset tracking) → STATUS OK per WRITE → CLOSE`.
      Respect the **remote** channel window when queueing WRITE packets —
      this is the first sender of bulk channel data, so remote-window
      accounting in `zcl_oassh_channel` finally gets exercised; add tests
      for stalling on window exhaustion and resuming on WINDOW_ADJUST.
- [ ] `sftp_upload( iv_path, iv_data, iv_timeout_seconds )`.
- [ ] Tier 1 (scripted), tier 2 (replay), tier 3 (upload then verify content
      via a second connection's download or forced `cat`).
- [ ] Rebex (`integration/rebex.mjs`): server is read-only — download-only
      check there; upload stays OpenSSH-only.

## S4 — Directory and metadata ops (by demand, order flexible)

- [ ] `STAT`/`LSTAT` → parsed ATTRS (needed anyway for pre-sizing downloads).
- [ ] `OPENDIR`/`READDIR` loop → list of names + ATTRS; `READDIR` repeats
      until `SSH_FX_EOF`.
- [ ] `MKDIR`/`RMDIR`/`REMOVE`/`RENAME` — thin, STATUS-checked wrappers.
- [ ] `REALPATH` for path normalization if servers disagree on relative paths.

## S5 — Validation & CI wrap-up

- [ ] CI: add sftp integration job(s) to `.github/workflows/test.yml`,
      pinned image, forced algorithms consistent with existing jobs.
- [ ] A4H: activate, ABAP Unit (focused + full), replay, ATC on changed scope.
- [ ] NPL SAP_BASIS 750: deploy via configured tooling, syntax-check, focused
      + replay tests. Live APC sftp download against Docker OpenSSH if
      reachable; otherwise record exactly what was blocked.
- [ ] README: sftp usage snippet; `CHECKLIST.md` M9 sftp item checked only
      when all tiers above are green.
- [ ] New transpiler/SAP discrepancies (uint64, chunk reassembly, int8) go to
      `ANORMALIES.md` with minimal repro.

## Portability traps specific to this work

- No `int8` reliance without proving identical behavior on NPL 750 **and**
  the transpiler; prefer `x LENGTH 8` + explicit conversion (see S0).
- READ loops contain early exits — keep one loop per method (transpiler
  sy-index scoping issue, see `ANORMALIES.md`).
- File content is binary: never route it through character types or
  `zcl_oassh_ascii`; watch `xstring` slicing into typed temporaries.
- Reassembly buffers must use chunk tables + balanced joins, not repeated
  `CONCATENATE ... IN BYTE MODE` on a growing xstring (O(n²) on large files).
- Uppercase hex at any handwritten JavaScript boundary.
