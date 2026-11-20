# Multi-operation SFTP sessions

Each method on `zif_oassh_sftp_one_shot` authenticates, opens a session channel,
starts the `sftp` subsystem, runs a single operation, and closes the channel.
Every operation therefore pays for a full SSH handshake
and a fresh subsystem — expensive when a caller needs several operations in a
row, and especially so on APC, where each handshake is exchanged one byte per
frame.

A multi-operation session removes that per-operation cost. `sftp_open` performs
the channel, subsystem, and INIT/VERSION handshake once; the same `sftp_*`
methods then run inside that single subsystem channel until `sftp_close`.

```abap
DATA li_sftp TYPE REF TO zif_oassh_sftp_session.
DATA lt_names TYPE zif_oassh_sftp_one_shot=>ty_names.
DATA lv_data TYPE xstring.
DATA ls_attrs TYPE zif_oassh_sftp_one_shot=>ty_attrs.

li_sftp = zcl_oassh=>connect(
  iv_host          = 'ssh.example.com'
  iv_port          = '22'
  iv_user          = 'deploy'
  iv_password      = 'secret'
  ii_host_verifier = lo_host_verifier ).

TRY.
    li_sftp->sftp_open( ).                       " channel + subsystem + INIT/VERSION
    lt_names = li_sftp->sftp_list( '/incoming' ).
    lv_data  = li_sftp->sftp_download( '/incoming/data.bin' ).
    ls_attrs = li_sftp->sftp_stat( '/incoming/data.bin' ).
    li_sftp->sftp_rename(
      iv_old_path = '/incoming/data.bin'
      iv_new_path = '/incoming/data.bin.done' ).
    li_sftp->sftp_close( ).                       " channel close handshake
  CLEANUP.
    li_sftp->close( ).
ENDTRY.
li_sftp->close( ).
```

## API

| Method | Purpose |
| --- | --- |
| `sftp_open( iv_timeout_seconds )` | Authenticate, open the session channel, start the `sftp` subsystem and complete the INIT/VERSION handshake. Returns once the session is ready. |
| `sftp_list` / `sftp_download` / `sftp_upload` / `sftp_stat` / `sftp_lstat` / `sftp_realpath` / `sftp_mkdir` / `sftp_rmdir` / `sftp_remove` / `sftp_rename` | The same methods as the one-shot API. Inside an open session they run over the existing channel instead of opening a new connection. |
| `sftp_close( iv_timeout_seconds )` | Send `CHANNEL_CLOSE` and wait for the peer's close. The socket stays open; call `close( )` separately. |

`sftp_open` is one operation per connection, like `execute`, `shell`, and
`exec_open`: calling it on a connection that already ran an operation raises the
usual typed error, and a session is never reused across those other kinds or a
second channel.

Use `zif_oassh_sftp_one_shot` when no reusable session is needed. The concrete
SFTP methods on `zcl_oassh` are implementation details; callers select one of
the two SFTP interfaces explicitly.

## Semantics

- **One operation at a time.** A session runs a single SFTP operation to
  completion before the next begins; there are no concurrent outstanding
  operations. Request ids keep counting across the whole session, so they stay
  unique.
- **Per-call timeouts.** `iv_timeout_seconds` applies to each individual call
  (`sftp_open`, every operation, `sftp_close`) rather than to the session as a
  whole, matching the one-shot methods.
- **Binary safety.** Downloads, uploads, filenames, and attributes remain
  byte-exact `xstring`/fixed-length byte data, unchanged from the one-shot API.
- **Rekeying is transparent.** A server-initiated key exchange during a long
  session is handled by the transport layer; operations continue across it.

## Session validity

A clean completion leaves the session usable for the next operation. This
**includes an SFTP status error** (for example, downloading a missing file):
the protocol layer closes any remote handle before finishing, the method raises
`zcx_oassh_error` with the SFTP status as usual, and the session stays open for
further calls.

A **timeout** or any **transport/protocol error** mid-operation leaves the
session in an undefined protocol position. The session is marked broken:
subsequent `sftp_*` calls raise a typed error, and only `close( )` remains
valid. `sftp_close` is still accepted on a broken session so the channel and
socket can be shut down cleanly.

## Scope

Out of scope, by design: concurrent outstanding operations, reusing one
connection across `execute`/`shell`/SFTP kinds, and reopening a second channel
after `sftp_close`. Request-id exhaustion (over two billion operations on one
channel) is outside the supported operation model.
