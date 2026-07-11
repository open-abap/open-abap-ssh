# open-abap-ssh — Checklist

## M0 — Foundations
- [x] `zcl_oassh_stream`: add mpint + byte helpers, fix inverted `boolean_decode`, full testclass
- [x] `zcl_oassh_ascii` — drop `cl_abap_char_utilities`; converts via the allowed `cl_abap_codepage`
- [x] `zif_oassh_socket` + `zif_oassh_random` interfaces, mock/fixed test implementations
- [x] move APC code to `zcl_oassh_socket_apc`; `zcl_oassh` depends only on interfaces
- [x] CI runs unit tests on push

## M1 — Hashing
- [x] `zcl_oassh_sha256` + NIST vectors (delegates to `cl_abap_message_digest`)
- [x] `zcl_oassh_hmac` + RFC 4231 vectors (delegates to `cl_abap_hmac`)

## M2 — Bigint & kex math
- [x] `zcl_oassh_bigint`: add/sub/cmp/mul/mod/modpow + tests
- [x] `zcl_oassh_x25519` + RFC 7748 vectors
- [x] `zcl_oassh_kdf` (exchange hash + key derivation) + captured-session vectors

## M3 — Symmetric crypto
- [x] `zcl_oassh_aes` + FIPS 197 vectors
- [x] `zcl_oassh_ctr` + SP 800-38A vectors

## M4 — Packet protocol & full kex ⭐
- [x] `zcl_oassh_packet`: framing, padding, MAC, sequence numbers
- [x] messages 20/21/30/31 complete; own algorithm proposal + random cookie
- [x] `zcl_oassh_transport` state machine through NEWKEYS
- [x] demo: encrypted transport against real OpenSSH (tier 3)

## M5 — Host key verification
- [x] `zcl_oassh_rsa` PKCS#1 v1.5 verify + vectors
- [x] verify server signature over `H`; known-hosts callback

## M6 — Authentication
- [x] messages 50–53 + SERVICE_REQUEST/ACCEPT (5/6)
- [x] `password` auth against Docker server (tier 3)

## M7 — Connection layer ⭐ v1.0
- [x] session channel: open, window management, exec, stdout/stderr, exit-status, close
- [x] API: `zcl_oassh=>connect( )->execute( 'uname -a' )`
- [ ] demo: run command on real server
  - [x] transpiled ABAP against Docker OpenSSH (`integration/exec.mjs`)
  - [ ] ECC via APC (`ztest_oassh` is ready; execution requires an ECC system)

## M8 — Hardening
- [x] table-of-xstring buffers (kill O(n²) concat) — `zcl_oassh_stream` read cursor + pending-chunk table
- [x] IGNORE/DEBUG/UNIMPLEMENTED + disconnect codes — messages 1–4 (parse/serialize) + central `handle_transport_message` wired into kex & encrypted receive loops; disconnect reason captured
- [ ] rekeying (server-initiated KEXINIT while ENCRYPTED; reuse session id, keep sequence numbers, swap keys)
- [ ] strict-kex (`kex-strict-c-v00@openssh.com`)
- [ ] timeouts, max packet sizes, malformed-packet fuzz fixtures

## M9 — Post-1.0
- [ ] `ssh-ed25519` host keys (SHA-512 + edwards)
- [ ] `publickey` auth
- [ ] `diffie-hellman-group14-sha256`
- [ ] `chacha20-poly1305@openssh.com`
- [ ] interactive shell, sftp, port forwarding

## Testing infrastructure (cross-cutting)
- [ ] tier 1: vectors in testclasses, run via transpiler (`npm test`)
- [ ] tier 2: recorded OpenSSH session replayed via mock socket + fixed RNG
- [ ] tier 3: GitHub Actions + Dockerized OpenSSH, Node socket shim, exec round-trip
- [ ] abaplint rule: no SAP standard outside the two platform adapters
