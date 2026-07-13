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
exchange and must return `abap_true` only for a trusted host key. Pass
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

An SSH client instance performs one command or SFTP operation. Open a fresh,
host-verified connection for each operation and close it in `CLEANUP` as well as
after the successful call. Downloads and uploads use `xstring` end to end:

```abap
DATA lv_file TYPE xstring.

lo_ssh = zcl_oassh=>connect(
  iv_host          = 'ssh.example.com'
  iv_port          = '22'
  iv_user          = 'deploy'
  iv_password      = 'secret'
  ii_host_verifier = lo_host_verifier ).

TRY.
    lv_file = lo_ssh->sftp_download(
      iv_path            = '/incoming/data.bin'
      iv_timeout_seconds = 60 ).
  CLEANUP.
    lo_ssh->close( ).
ENDTRY.
lo_ssh->close( ).
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
file. Host-key verification remains mandatory for every fresh connection.

## Node.js development and transpiled usage

Install Node.js and npm, then clone and validate the project:

```sh
git clone https://github.com/open-abap/open-abap-ssh.git
cd open-abap-ssh
npm ci
npm test
```

`npm test` checks platform-dependency boundaries, runs abaplint, transpiles the
ABAP sources, and executes the ABAP Unit suite on Node.js. Generated files are
written to `output/`; do not edit or commit that directory.

The repository includes a Node TCP adapter and an executable example in
`integration/exec.mjs`. With an SSH server already listening, configure it via
environment variables and run:

```sh
OASSH_HOST=127.0.0.1 \
OASSH_PORT=2222 \
OASSH_USER=test \
OASSH_PASSWORD=test \
OASSH_COMMAND='printf open-abap-ssh' \
OASSH_EXPECTED='open-abap-ssh' \
npm run integration:exec
```

On PowerShell, set the same values with `$env:OASSH_HOST = '127.0.0.1'` (and
the corresponding variables) before running `npm run integration:exec`.
`OASSH_PRIVATE_SEED` can replace `OASSH_PASSWORD` and must contain the
hexadecimal Ed25519 seed. The integration adapter uses Node's secure random
generator, but its accept-all host verifier is suitable only for local tests.

Additional live checks are available as `npm run integration:transport` and
`npm run integration:auth`. `npm run integration:shell` requests a real PTY,
starts the account's default shell, sends binary stdin followed by SSH channel
EOF, and verifies raw terminal output against the pinned OpenSSH server.

`npm run integration:rebex` runs all three scenarios against the public
[Rebex test server](https://test.rebex.net) (`demo`/`password`), an
independent non-OpenSSH implementation, with no local setup required. It
needs internet access and depends on third-party uptime, so CI runs it as a
non-blocking job.

## Supported protocol features

- Key exchange: `curve25519-sha256`, `diffie-hellman-group14-sha256`
- Host keys: `rsa-sha2-256`, `ssh-ed25519`
- Ciphers: `aes128-ctr`, `chacha20-poly1305@openssh.com`
- Authentication: password and Ed25519 public key
- Session command execution, stdout/stderr, exit status, rekeying, and strict KEX
- Interactive PTY shell sessions with binary stdin and raw terminal output
- SFTP v3: binary download/upload, STAT/LSTAT, directory listing, REALPATH,
  MKDIR/RMDIR, REMOVE, and RENAME

Port forwarding is intentionally out of scope.

## Protocol references

- [RFC 4251 — SSH Protocol Architecture](https://datatracker.ietf.org/doc/html/rfc4251)
- [RFC 4252 — SSH Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252)
- [RFC 4253 — SSH Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)
- [RFC 4254 — SSH Connection Protocol](https://datatracker.ietf.org/doc/html/rfc4254)

## License

[MIT](LICENSE)
