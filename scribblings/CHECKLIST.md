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
- [ ] demo: run command from transpiled ABAP and an actual ECC system
  - [x] transpiled ABAP against Docker OpenSSH (`integration/exec.mjs`)
  - [x] on-premise AS ABAP via APC — NPL SAP_BASIS 750 executed `printf open-abap-ssh`
        against Docker OpenSSH; ABAP Unit live runner passed in 43.13 s
  - [ ] actual ECC system via APC

## M8 — Hardening
- [x] table-of-xstring buffers (kill O(n²) concat) — `zcl_oassh_stream` read cursor + pending-chunk table
- [x] IGNORE/DEBUG/UNIMPLEMENTED + disconnect codes — messages 1–4 (parse/serialize) + central `handle_transport_message` wired into kex & encrypted receive loops; disconnect reason captured
- [x] rekeying (server-initiated KEXINIT while ENCRYPTED; reuse session id, keep sequence numbers, swap keys)
- [x] strict-kex (`kex-strict-c` + `kex-strict-c-v00@openssh.com`; initial-KEX message discipline,
      retrospective first-packet check, and directional sequence resets after every NEWKEYS)
- [x] uint32 packet sequence rollover without signed ABAP integer overflow
- [x] channel receive-window replenishment and chunked large-output accumulation
- [x] byte-safe balanced CTR keystream joining across SAP and open-abap
- [x] balanced stream materialization for high chunk counts
- [x] strict canonical RFC 4251 name-list validation before negotiation
- [x] configurable execute/APC timeout with typed error, RFC 4253 payload/wire-size ceilings,
      deterministic malformed/MAC/oversize packet fixtures

## M9 — Post-1.0
- [x] `ssh-ed25519` host keys — SHA-512, canonical Edwards decoding,
  cofactored verification, forced OpenSSH integration, A4H/NPL ABAP Unit
- [x] `publickey` auth — Ed25519 seed signing, RFC 4252 session binding,
  password-disabled OpenSSH integration, A4H/NPL ABAP Unit
- [x] `diffie-hellman-group14-sha256`
- [x] `chacha20-poly1305@openssh.com` — RFC 8439/OpenSSH vectors,
  authenticated streaming packets, forced OpenSSH integration, A4H/NPL ABAP Unit
- [ ] interactive shell, sftp, port forwarding
  - sftp: implementation plan and milestone checklist in `CHECKLIST2.md`

## Testing infrastructure (cross-cutting)
- [x] tier 1: vectors in testclasses, run via transpiler (`npm test`)
- [x] tier 2: recorded OpenSSH session replayed via mock socket + fixed RNG
- [x] tier 3: GitHub Actions + Dockerized OpenSSH, Node socket shim, exec round-trip
- [x] CI dependency gate: no SAP standard outside the documented adapters/exceptions
