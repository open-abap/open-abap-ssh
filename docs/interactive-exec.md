# Interactive exec

`zcl_oassh=>execute( )` is one-shot: it starts a command, waits for the
channel to close and returns the collected stdout as text. Some remote
commands are conversations instead — the client must read a server
response, decide, and write the next request while the command keeps
running. The canonical example is `git-upload-pack`, which GitHub exposes
to deploy keys: ref advertisement down, `want`/`done` up, packfile down.

The `zif_oassh_interactive_exec` interface keeps the session channel open and
hands the byte streams to the caller:

| Method | Purpose |
| --- | --- |
| `exec_open( iv_command, iv_timeout_seconds )` | Authenticate, open the session channel and start the command. Returns once the server accepts the exec request. |
| `exec_read( iv_timeout_seconds )` | Return the stdout bytes buffered since the previous call; reads from the socket only when nothing is buffered. |
| `exec_write( iv_data )` | Queue stdin bytes and send what the remote window allows. |
| `exec_eof( )` | Half-close: no more stdin, output continues. |
| `exec_close( iv_timeout_seconds )` | Send `CHANNEL_CLOSE` and wait for the peer's close. |
| `exec_is_closed( )` | `abap_true` when no further stdout can arrive. |

All data is binary (`xstring`); nothing is decoded as text. Stderr and the
exit status are available through the existing `get_stderr( )` and
`get_exit_status( )` after `exec_close( )`.

## Read semantics

`exec_read( )` mirrors `zif_oassh_socket~read`: an empty result means the
timeout expired while `exec_is_closed( )` is `abap_false`, otherwise the
command's output stream has ended (the peer sent `CHANNEL_EOF` or the
connection closed). Callers therefore loop:

```abap
DATA li_exec TYPE REF TO zif_oassh_interactive_exec.

li_exec = zcl_oassh=>connect(
  iv_host          = 'github.com'
  iv_port          = '22'
  iv_user          = 'git'
  iv_private_seed  = lv_ed25519_seed   " the deploy key
  ii_host_verifier = li_verifier ).

li_exec->exec_open( |git-upload-pack 'owner/repo.git'| ).

DATA(lv_advertisement) = VALUE xstring( ).
WHILE li_exec->exec_is_closed( ) = abap_false.
  DATA(lv_chunk) = li_exec->exec_read( ).
  IF lv_chunk IS INITIAL.
    EXIT. " timeout: decide whether the protocol layer has a complete unit
  ENDIF.
  CONCATENATE lv_advertisement lv_chunk INTO lv_advertisement IN BYTE MODE.
  " ... hand to a pkt-line parser, stop when it has the full advertisement
ENDWHILE.

li_exec->exec_write( lv_want_request ). " pkt-lines: want, deepen, flush, done
" ... read the packfile with the same exec_read loop
li_exec->exec_close( ).
li_exec->close( ).
```

## Flow control

`exec_write( )` respects the remote window (RFC 4254 section 5.2): bytes
that do not fit are queued and sent automatically when the server's
`WINDOW_ADJUST` arrives during a later `exec_read( )` or `exec_close( )`.
`exec_eof( )` refuses to half-close while stdin is still queued, because
those bytes could never be delivered afterwards.

Like every other workflow, an interactive exec is the one operation of its
connection object: `exec_open( )` on a connection that
already ran an operation raises the usual typed error.

## Scope

This is the transport layer ("layer 0") for a fetch-only git client on top
of this library. The layers above it — pkt-line framing, the upload-pack
conversation, and the packfile decoder (raw-zlib inflate, SHA-1,
ref-delta) — are protocol code that does not touch SSH and can be built
and tested independently against recorded byte fixtures.
