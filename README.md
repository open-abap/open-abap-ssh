# open-abap-ssh

An SSH-2 client implemented in portable ABAP. It can connect to OpenSSH,
authenticate with a password or an Ed25519 private seed, execute a command, and
return its stdout, stderr, and exit status. It also supports binary-safe SFTP
file transfer, metadata, directory listing, path normalization, and basic path
mutation operations.

The client runs on SAP systems through ABAP Push Channels (APC) and on Node.js
after transpilation with open-abap. SAP_BASIS 750 is the compatibility floor.
Steampunk is not currently supported because it does not provide unrestricted
TCP/IP sockets.

## Security notice — use at your own risk

Most of the cryptography in this library (AES-CTR, ChaCha20-Poly1305, X25519,
Ed25519, RSA signature verification, Diffie-Hellman group14, and the
big-integer arithmetic under them) is implemented from scratch in ABAP; only
SHA-2 hashing and HMAC delegate to the kernel-backed SAP classes. None of it
has undergone an independent security audit, and ABAP offers no constant-time
execution guarantees, so timing side channels cannot be ruled out. The unit
tests cover published test vectors and the integration tests exercise real
OpenSSH, but that is not the same as a cryptographic review.

Before relying on this library for anything security-sensitive, review the
code — the protocol layer as well as everything under `src/crypto/` — against
your own threat model, and decide deliberately whether a from-scratch ABAP
implementation is acceptable for your use case. The software is provided "as
is", without warranty of any kind, as stated in the [MIT license](LICENSE);
you use it at your own risk. Security findings are welcome as issues or pull
requests.

## Installation on an SAP system

Import this repository with [abapGit](https://abapgit.org/) into a package of
your choice:

```text
https://github.com/open-abap/open-abap-ssh.git
```

Activate the imported objects. The APC socket adapter requires the target SAP
system to support outbound TCP connections through APC and to permit the SSH
host and port in its network configuration.

The library deliberately does not choose the following security policy for the
application:

- Implement `zif_oassh_host_verifier` to validate or pin the server host key.

On SAP, `zcl_oassh_random_secure` is used by default and obtains bytes from the
kernel-backed `GENERATE_SEC_RANDOM` function module. A caller can still inject a
different `zif_oassh_random` implementation for another runtime.
`zcl_oassh_random_fixed` is deterministic and exists for tests; do not use it
for production connections. Likewise, do not use an accept-all host verifier
outside an isolated test environment.

### Performance

Expect modest throughput on SAP. The APC TCP frame is defined as one fixed byte,
so the adapter both receives and sends one byte per APC message and the SSH core
reassembles the stream. Every outbound SSH packet is therefore emitted as many
single-byte messages, and a full handshake plus transfer exchanges a large
number of tiny frames. This is a correctness-over-speed trade-off in the APC
socket adapter, not a protocol limitation, so it is best suited to command
execution and small-to-moderate file transfers rather than high-volume data
movement.

## ABAP usage

Pass a host-verification implementation to `zcl_oassh=>connect`, then execute a
command. Supplying `ii_random` is optional on SAP:

```abap
DATA lo_host_verifier TYPE REF TO zif_oassh_host_verifier.
DATA lo_ssh TYPE REF TO zcl_oassh.
DATA lv_stdout TYPE string.
DATA lv_stderr TYPE string.
DATA lv_exit_status TYPE i.

lo_host_verifier = NEW zcl_my_known_hosts_verifier( ).

lo_ssh = zcl_oassh=>connect(
  iv_host          = 'ssh.example.com'
  iv_port          = '22'
  iv_user          = 'deploy'
  iv_password      = 'secret'
  ii_host_verifier = lo_host_verifier ).

TRY.
    lv_stdout = lo_ssh->execute(
      iv_command         = 'uname -a'
      iv_timeout_seconds = 60 ).
    lv_stderr = lo_ssh->get_stderr( ).
    lv_exit_status = lo_ssh->get_exit_status( ).
  CLEANUP.
    lo_ssh->close( ).
ENDTRY.
lo_ssh->close( ).
```

Replace `zcl_my_known_hosts_verifier` with an application-specific class
implementing `zif_oassh_host_verifier`. The verifier is called during key
exchange with `iv_host`, `iv_port`, and the complete `iv_host_key` blob. It
must return `abap_true` only when that exact endpoint-to-key association is
trusted. Pass
`ii_random` explicitly only when a platform-specific implementation or a
deterministic test source is required.

For public-key authentication, supply a 32-byte Ed25519 seed instead of a
password:

```abap
lo_ssh = zcl_oassh=>connect(
  iv_host          = 'ssh.example.com'
  iv_port          = '22'
  iv_user          = 'deploy'
  iv_private_seed  = lv_ed25519_seed
  ii_random        = lo_random
  ii_host_verifier = lo_host_verifier ).
```

Keep private seeds and passwords outside source code and transport them through
the platform's secret-management facilities.

### Interactive shell

`shell` requests a pseudo-terminal and the account's default shell. Input and
output are `xstring` because terminal streams may contain control sequences or
bytes that are not valid UTF-8. The method sends all supplied input under SSH
channel flow control, sends channel EOF, and waits for the remote shell to exit:

```abap
DATA lv_terminal_input TYPE xstring.
DATA lv_terminal_output TYPE xstring.

lv_terminal_input = cl_abap_codepage=>convert_to( |printf ready\nexit\n| ).
lv_terminal_output = lo_ssh->shell(
  iv_input           = lv_terminal_input
  iv_terminal        = 'xterm'
  iv_columns         = 80
  iv_rows            = 24
  iv_timeout_seconds = 60 ).
```

A PTY normally echoes input and may add prompts or terminal-control bytes, so
callers should parse the raw stream according to their terminal needs. As with
`execute` and SFTP, a client instance owns one operation; create a fresh,
host-verified connection for another session.

### SFTP

Use `zif_oassh_sftp_one_shot` on a fresh connection for one operation. It opens
its own channel and subsystem, runs the operation, and closes the channel.
Downloads and uploads use `xstring` end to end:

```abap
DATA lv_file TYPE xstring.
DATA li_sftp TYPE REF TO zif_oassh_sftp_one_shot.

li_sftp = zcl_oassh=>connect(
  iv_host          = 'ssh.example.com'
  iv_port          = '22'
  iv_user          = 'deploy'
  iv_password      = 'secret'
  ii_host_verifier = lo_host_verifier ).

TRY.
    lv_file = li_sftp->sftp_download(
      iv_path            = '/incoming/data.bin'
      iv_timeout_seconds = 60 ).
  CLEANUP.
    li_sftp->close( ).
ENDTRY.
li_sftp->close( ).
```

The public SFTP methods are:

- `sftp_download` and `sftp_upload` for binary file contents.
- `sftp_stat` and `sftp_lstat` for byte-exact v3 attributes, including unsigned
  32-bit and 64-bit fields represented as fixed-length byte types.
- `sftp_list` for binary-safe filenames, opaque longnames, and parsed attributes.
- `sftp_realpath` for the canonical NAME result and its attributes.
- `sftp_mkdir`, `sftp_rmdir`, `sftp_remove`, and `sftp_rename` for
  STATUS-checked path mutations.

SFTP status failures raise `zcx_oassh_error` through `cx_static_check`; inspect
the typed reason and SFTP status rather than treating every failure as a missing
file.

#### Multi-operation SFTP sessions

To run several SFTP operations over a single authenticated connection, use
`zif_oassh_sftp_session` and call `sftp_open` first. It performs the channel,
subsystem, and INIT/VERSION
handshake once; the same `sftp_*` methods then run inside that session until
`sftp_close`. This avoids repeating the full SSH handshake — and, on APC, the
one-byte-per-frame cost of every handshake — for each operation:

```abap
DATA li_sftp TYPE REF TO zif_oassh_sftp_session.
li_sftp = zcl_oassh=>connect( ... ).
TRY.
    li_sftp->sftp_open( ).
    lt_names = li_sftp->sftp_list( '/incoming' ).
    lv_file  = li_sftp->sftp_download( '/incoming/data.bin' ).
    ls_attrs = li_sftp->sftp_stat( '/incoming/data.bin' ).
    li_sftp->sftp_close( ).
  CLEANUP.
    li_sftp->close( ).
ENDTRY.
li_sftp->close( ).
```

One SFTP operation runs at a time, and the session is not reused across
`execute`/`shell` or a second channel. A clean completion — including an SFTP
status error — leaves the session usable for the next operation; a timeout or
transport error marks it broken so only `close` remains. See
[docs/sftp-sessions.md](docs/sftp-sessions.md) for the full API, per-call
timeouts, and session-validity rules.

Host-key verification remains mandatory for every fresh connection, whether the
SFTP methods are used one-shot or inside a session.

## Node.js development and transpiled usage

See [docs/nodejs-development.md](docs/nodejs-development.md) for installing the
toolchain, running `npm test`, and exercising the live integration scenarios.

## Supported protocol features

- Key exchange: `curve25519-sha256`, `diffie-hellman-group14-sha256`
- Host keys: `rsa-sha2-256`, `ssh-ed25519`
- Ciphers: `aes128-ctr`, `chacha20-poly1305@openssh.com`
- Authentication: password and Ed25519 public key
- Session command execution, stdout/stderr, exit status, rekeying, and strict KEX
- Interactive PTY shell sessions with binary stdin and raw terminal output
- SFTP v3: binary download/upload, STAT/LSTAT, directory listing, REALPATH,
  MKDIR/RMDIR, REMOVE, and RENAME, one-shot or over a multi-operation session

Port forwarding is intentionally out of scope.

## License

[MIT](LICENSE)
