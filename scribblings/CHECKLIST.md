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
- [x] RFC 4253 wrong `first_kex_packet_follows` guess discard
- [x] reject nonzero KEXINIT reserved fields
- [x] RFC 4254 replies for recognized and unknown server channel requests
- [x] reject channel messages in invalid lifecycle states
- [x] linear zero-copy ASCII conversion fast path for large command output
- [x] accept the advertised 32 KiB channel data plus its SSH message envelope
- [x] propagate APC handler completion after callback exceptions
- [x] bound and validate canonical RSA host-key parameters before bigint work
- [x] full-length HMAC comparison without first-mismatch timing leakage
- [x] reject all-zero X25519 shared secrets from low-order peer values
- [x] reject authentication replies before an authentication request exists
- [x] linear conversion fast path for valid SSH identifiers and banners
- [x] RFC-compliant server pre-banner and bounded identification parsing
- [x] strict SSH protocol/software identification grammar validation
- [x] unsigned 32-bit channel-window adjustment with overflow rejection
- [x] typed parsing of server channel-open failures
- [x] exact wire-byte validation of nested host-key algorithm names
- [x] exact wire-byte validation of service, request, and auth method tokens
- [x] typed execute failures for invalid timeouts and pre-channel socket errors
- [x] RFC-compliant UTF-8 credentials and non-ASCII exec commands
- [x] preserve UTF-8 stdout/stderr while filtering unsafe ASCII controls
- [x] release execute waits immediately on premature transport close
- [x] send each APC TCP packet as one binary frame instead of one call per byte
- [x] bound unterminated server pre-banner buffering before authentication
- [x] incremental O(n) identification scanning across one-byte APC frames
- [x] track execute lifecycle independently of command text so an empty exec
      command opens a channel and remains subject to the one-shot API guard
- [x] avoid quadratic filtered-output rebuilding by joining valid byte runs
      in a balanced tree, including alternating binary/control output
- [x] accept the advertised 32 KiB stderr data with its larger
      `CHANNEL_EXTENDED_DATA` envelope while rejecting one byte more
- [x] reject server host-key algorithms omitted from the client's KEXINIT,
      including Ed25519 when its offer switch is disabled
- [x] distinguish an omitted password from a legal explicitly empty password
      through the public API and password-authentication wire request
- [x] fall back once from a rejected public key to a supplied password when
      `USERAUTH_FAILURE` lists password as a method that can continue
- [x] assemble multi-block OpenSSH ChaCha20 output through the balanced stream
      buffer instead of repeatedly copying the growing ciphertext prefix
- [x] make fragmented receive-buffer length checks constant-time without
      materializing pending one-byte APC frames before packet consumption
- [x] cache the validated plaintext KEX packet length across fragmented
      callbacks instead of repeatedly peeking and materializing its prefix
- [x] scan identification CRLF directly across pending APC chunks and cache
      the `SSH-` prefix decision without rebuilding the growing line
- [x] terminate immediately on peer `SSH_MSG_DISCONNECT` and leave any later
      buffered packets unaccepted, in both plaintext and encrypted receive loops
- [x] reject socket callbacks already queued after peer disconnect and avoid
      retaining zero-length receive chunks from empty callbacks
- [x] validate complete channel-message shapes before committing remote IDs,
      window credit, output, exit status, EOF, or close state
- [x] make disconnect, authentication, and KEX-reply parsing atomic; publish
      K/H only after authentication and verify possession before host-key trust
- [x] reduce same-limb Montgomery bases when `base >= modulus`, and normalize
      long leading-zero bigint prefixes with one final slice instead of O(n²) copies
- [x] initialize Montgomery exponentiation directly from its leading set bit,
      eliminating two redundant O(n²) limb multiplications per modpow
- [x] keep Montgomery operands at fixed modulus width and multiply directly
      from caller tables, avoiding two table copies/padding passes per inner call
- [x] enforce RFC 8017's `3 <= e <= n - 1` RSA exponent range before modpow,
      rejecting oversized attacker-controlled exponents before expensive work
- [x] enforce the RSA 1024-bit security floor by actual modulus bit length,
      not only the rounded 128-byte encoded length
- [x] discard empty stdout/stderr channel chunks so zero-byte DATA packets
      cannot grow output tables without consuming receive-window credit
- [x] answer unsupported plaintext and encrypted message numbers with RFC 4253
      `SSH_MSG_UNIMPLEMENTED`, including the rejected uint32 sequence at rollover
- [x] reject unsolicited server `CHANNEL_OPEN` requests with RFC 4254
      `OPEN_ADMINISTRATIVELY_PROHIBITED` instead of aborting the connection
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
  - [x] interactive shell: RFC 4254 PTY request, checked shell request,
        window-aware binary stdin, client EOF, raw terminal output, exact
        fixed-RNG OpenSSH replay, and pinned live OpenSSH CI
  - sftp: implementation plan and milestone checklist in `CHECKLIST2.md`
  - [ ] port forwarding

## Testing infrastructure (cross-cutting)
- [x] tier 1: vectors in testclasses, run via transpiler (`npm test`)
- [x] tier 2: recorded OpenSSH session replayed via mock socket + fixed RNG
- [x] tier 3: GitHub Actions + Dockerized OpenSSH, Node socket shim, exec round-trip
- [x] CI dependency gate: no SAP standard outside the documented adapters/exceptions
