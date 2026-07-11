# open-abap-ssh — Checklist

## M0 — Foundations
- [ ] `zcl_oassh_stream`: add mpint + byte helpers, fix inverted `boolean_decode`, full testclass
- [ ] `zcl_oassh_ascii` — replace `cl_abap_codepage` / `cl_abap_char_utilities`
- [ ] `zif_oassh_socket` + `zif_oassh_random` interfaces, mock/fixed test implementations
- [ ] move APC code to `zcl_oassh_socket_apc`; `zcl_oassh` depends only on interfaces
- [ ] CI runs unit tests on push

## M1 — Hashing
- [ ] `zcl_oassh_sha256` + NIST vectors
- [ ] `zcl_oassh_hmac` + RFC 4231 vectors

## M2 — Bigint & kex math
- [ ] `zcl_oassh_bigint`: add/sub/cmp/mul/mod/modpow + tests
- [ ] `zcl_oassh_x25519` + RFC 7748 vectors
- [ ] `zcl_oassh_kdf` (exchange hash + key derivation) + captured-session vectors

## M3 — Symmetric crypto
- [ ] `zcl_oassh_aes` + FIPS 197 vectors
- [ ] `zcl_oassh_ctr` + SP 800-38A vectors

## M4 — Packet protocol & full kex ⭐
- [ ] `zcl_oassh_packet`: framing, padding, MAC, sequence numbers
- [ ] messages 20/21/30/31 complete; own algorithm proposal + random cookie
- [ ] `zcl_oassh_transport` state machine through NEWKEYS
- [ ] demo: encrypted transport against real OpenSSH (tier 3)

## M5 — Host key verification
- [ ] `zcl_oassh_rsa` PKCS#1 v1.5 verify + vectors
- [ ] verify server signature over `H`; known-hosts callback

## M6 — Authentication
- [ ] messages 50–53 + SERVICE_REQUEST/ACCEPT (5/6)
- [ ] `password` auth against Docker server (tier 3)

## M7 — Connection layer ⭐ v1.0
- [ ] session channel: open, window management, exec, stdout/stderr, exit-status, close
- [ ] API: `zcl_oassh=>connect( )->execute( 'uname -a' )`
- [ ] demo: run command on real server — transpiled and on ECC

## M8 — Hardening
- [ ] table-of-xstring buffers (kill O(n²) concat)
- [ ] rekeying, IGNORE/DEBUG/UNIMPLEMENTED, disconnect codes
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
