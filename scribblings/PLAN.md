# open-abap-ssh — Grand Implementation Plan

Goal: a working **SSH-2 client written in pure ABAP**, able to connect to an OpenSSH
server, authenticate, and execute a command. Runs on:

- **Node.js** via the [abap transpiler](https://github.com/abaplint/transpiler) +
  [open-abap](https://github.com/open-abap/open-abap) — this is the primary
  development and test target
- **ECC / on-prem ABAP** via APC TCP sockets (`cl_apc_tcp_client_manager`)
- **Steampunk** if/when it supports raw TCP

Guiding principle: **as little SAP standard as possible**. Everything that is not
plain ABAP language (crypto, encoding, sockets, randomness) is either implemented
from scratch in ABAP or hidden behind a tiny injectable interface with one
platform-specific implementation per target.

**Exception — allowed standard classes**: `cl_abap_message_digest`, `cl_abap_hmac`
and `cl_abap_codepage` may be called directly from core code. They are
kernel-backed on any NW 7.02+ system (including ECC) and implemented in
[open-abap-core](https://github.com/open-abap/open-abap-core) via Node `crypto`
for the transpiler target, so they are fast and portable on both runtimes.
`cl_abap_bigint` is explicitly **not** allowed — bigint performance is fixed
locally in `zcl_oassh_bigint`.

Relevant RFCs:

| RFC | Topic |
|---|---|
| [4251](https://datatracker.ietf.org/doc/html/rfc4251) | SSH architecture, wire data types |
| [4253](https://datatracker.ietf.org/doc/html/rfc4253) | Transport layer: version exchange, binary packets, kex |
| [4252](https://datatracker.ietf.org/doc/html/rfc4252) | Authentication protocol |
| [4254](https://datatracker.ietf.org/doc/html/rfc4254) | Connection protocol: channels, exec |
| [5656](https://datatracker.ietf.org/doc/html/rfc5656) | ECDH kex message format (30/31) |
| [7748](https://datatracker.ietf.org/doc/html/rfc7748) | X25519 |
| [8709](https://datatracker.ietf.org/doc/html/rfc8709) | ed25519 host keys |

---

## 1. Scope: the minimal interoperable algorithm suite

The whole point of algorithm negotiation is that we only need **one** algorithm per
category to interoperate with stock OpenSSH. Chosen to minimize the amount of crypto
we must hand-write in ABAP:

| Category | First target | Why | Later |
|---|---|---|---|
| Key exchange | `curve25519-sha256` | fixed-size 32-byte keys, Montgomery ladder, no point validation headaches; message classes 30/31 already exist | `diffie-hellman-group14-sha256` (only needs bignum modpow, good fallback) |
| Host key | `rsa-sha2-256` | verification is just modpow + PKCS#1 v1.5 padding check — reuses the bignum | `ssh-ed25519` |
| Cipher | `aes128-ctr` | AES core is table-driven and well documented; CTR needs encrypt-only | `chacha20-poly1305@openssh.com` |
| MAC | `hmac-sha2-256` | needs SHA-256, which kex needs anyway | `hmac-sha2-512` |
| Compression | `none` | — | never |
| Auth | `password` | no client-side crypto at all | `publickey` |

Shared crypto foundation this implies, **all pure ABAP**:

1. **SHA-256** (kex hash, HMAC, RSA signature digest)
2. **HMAC-SHA-256** (trivial once SHA-256 exists)
3. **Big unsigned integers** over `xstring`: add, sub, compare, mul, mod, modpow
   (needed for RSA verify and DH group14)
4. **X25519** (RFC 7748: field arithmetic mod 2^255−19 on top of the bignum,
   Montgomery ladder)
5. **AES-128 block cipher + CTR mode** (encrypt-only)
6. **SHA-512** (only when ed25519 is added)

---

## 2. Architecture & class inventory

Layered exactly like the RFCs. Prefix `zcl_oassh_*` / `zif_oassh_*` (established).

```
                    zcl_oassh  (public API: connect / execute / close)
                        │
        ┌───────────────┼────────────────┐
   RFC 4252 auth   RFC 4254 channels     │
        └───────────────┬────────────────┘
              zcl_oassh_transport  (RFC 4253: packets, kex, keys, seq numbers)
                        │
              zcl_oassh_packet     (binary packet framing, pad, MAC, cipher)
                        │
              zif_oassh_socket ◄── injectable: APC TCP / Node net / mock
```

### 2.1 Platform abstraction (the only impure corners)

| Interface | Purpose | ECC impl | Transpiler impl | Test impl |
|---|---|---|---|---|
| `zif_oassh_socket` | `connect / send / receive / close`, blocking byte stream | wraps `cl_apc_tcp_client_manager` (1-byte frames, as today) | thin ABAP shell whose transpiled body is replaced by a Node.js `net.Socket` module in the test harness | `zcl_oassh_socket_mock` replaying recorded byte streams |
| `zif_oassh_random` | `bytes( iv_length )` CSPRNG | SAP PRNG wrapper (isolated in one class) | Node `crypto.randomBytes` shim | deterministic fixed bytes, so full handshakes are reproducible |

Everything above these two interfaces is deterministic, pure ABAP, and unit-testable
offline. This is what makes the transpiler test setup work.

`cl_abap_char_utilities` usage gets removed: SSH identifiers are ASCII, so a
small `zcl_oassh_ascii` (string ⇄ xstring, CRLF constant, non-printable
filtering) replaces it, delegating the raw conversion to the allowed
`cl_abap_codepage`.

### 2.2 Wire encoding — `zcl_oassh_stream` (exists, extend)

Already has: uint32, boolean, string, name-list, take/append/peek.
Still needed:

- `mpint_encode` / `mpint_decode` (RFC 4251 §5 — sign-bit padding rules, used by kex)
- `byte( )` single-byte take, `uint8` helpers
- fix `boolean_decode` (currently inverted: `'00'` must be false)
- performance pass later: `mv_hex = mv_hex && iv_hex` is O(n²) — acceptable now,
  revisit in the hardening milestone

### 2.3 Messages — one class per message type (pattern exists)

Each `zcl_oassh_message_<nn>` is a dumb `parse( stream ) → ty_data` /
`serialize( ty_data ) → stream` pair. Inventory:

| Class | Msg | RFC | Status |
|---|---|---|---|
| `zcl_oassh_message_20` KEXINIT | 20 | 4253 §7.1 | exists |
| `zcl_oassh_message_21` NEWKEYS | 21 | 4253 §7.3 | new |
| `zcl_oassh_message_ecdh_30/31` | 30/31 | 5656 §4 | exist, finish |
| `zcl_oassh_message_1/2/3/4` DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG | 1–4 | 4253 §11 | new |
| `zcl_oassh_message_50/51/52/53` USERAUTH_REQUEST / FAILURE / SUCCESS / BANNER | 50–53 | 4252 | new |
| `zcl_oassh_message_90/91/93/94` CHANNEL_OPEN / CONFIRMATION / WINDOW_ADJUST / DATA | 90+ | 4254 | new |
| `zcl_oassh_message_95..100` EXTENDED_DATA, EOF, CLOSE, REQUEST, SUCCESS/FAILURE | 95–100 | 4254 | new |

### 2.4 Crypto — `zcl_oassh_hash_*`, `zcl_oassh_cipher_*`, `zcl_oassh_bigint`

- `zcl_oassh_sha256` — thin wrapper over `cl_abap_message_digest`
- `zcl_oassh_hmac` — thin wrapper over `cl_abap_hmac`
- `zcl_oassh_bigint` — unsigned big integers on `xstring`
- `zcl_oassh_x25519` — `scalarmult( k, u )`, clamping per RFC 7748
- `zcl_oassh_aes` + `zcl_oassh_ctr` — block core + counter mode
- `zcl_oassh_rsa` — `verify_pkcs1_sha256( n, e, sig, message )`
- `zcl_oassh_kdf` — key derivation `HASH(K || H || "A".."F" || session_id)`
  (RFC 4253 §7.2)

### 2.5 Engine — `zcl_oassh_transport`

State machine replacing the ad-hoc `CASE mv_state` in `zcl_oassh`:

```
VERSION_EXCHANGE → KEXINIT_SENT → ECDH_SENT → NEWKEYS → ENCRYPTED
       (rekey re-enters KEXINIT from ENCRYPTED — later milestone)
```

Owns: send/receive sequence numbers, negotiated algorithms, session keys,
exchange-hash `H` and session id, packet encrypt/decrypt + MAC verify.

---

## 3. Testing strategy (transpiler + open-abap, first-class)

The existing toolchain stays: `npm test` = `abaplint` + transpile via
`abap_transpile.json` (open-abap as lib) + run `output/index.mjs` on Node.
`write_unit_tests: true` already makes the transpiler emit a runner for all
ABAP Unit `testclasses`. Three tiers:

### Tier 1 — pure unit tests (every commit, no network)

`*.clas.testclasses.abap` next to every class; the transpiler runs them on Node:

- **Wire codecs**: round-trip every stream type; mpint edge cases from RFC 4251 §5
  examples (`0`, `9a378f9b2e332a7`, negative-flag padding)
- **Crypto against official vectors**, hardcoded in the testclasses:
  - SHA-256: NIST FIPS 180-4 / RFC 6234 vectors
  - HMAC-SHA-256: RFC 4231 test cases 1–7
  - X25519: RFC 7748 §5.2 vectors + the two Diffie-Hellman vectors in §6.1
  - AES-128: FIPS 197 appendix, CTR: NIST SP 800-38A F.5
  - bigint: modpow vs. precomputed values, boundary sizes
- **Messages**: parse/serialize round-trips on byte captures of real OpenSSH
  packets (checked into `test/fixtures/` as hex constants)
- **KDF / exchange hash**: full recorded handshake with a fixed RNG — assert the
  derived keys byte-for-byte against a captured session

### Tier 2 — offline handshake tests (every commit, no network)

`zcl_oassh_socket_mock` + fixed `zif_oassh_random` replay a **recorded
OpenSSH session** (captured once with a patched client or `ssh -vvv` + tcpdump):
the full client runs VERSION → KEX → NEWKEYS → AUTH → EXEC against canned bytes.
This is the highest-value test: it exercises the whole state machine
deterministically in plain `npm test`.

Implemented with a capture from the pinned OpenSSH 10.3 CI container: the test
replays all 3,134 inbound bytes and verifies the exact 678-byte client stream.

### Tier 3 — live integration (CI job, real network)

GitHub Actions workflow (`.github/workflows/test.yml`, extend):

1. Start `linuxserver/openssh-server` (password auth enabled) as a service
   container
2. Transpile, then run a small Node driver that instantiates the transpiled
   `zcl_oassh` with the **Node socket implementation** of `zif_oassh_socket`
   (a hand-written `.mjs` module registered with the transpiler runtime)
3. Assert: handshake completes, `exec("echo hello")` returns `hello`, clean
   disconnect
4. Matrix later: multiple OpenSSH versions, multiple negotiated suites

Local dev loop: `docker run -p 2222:2222 ...` + `npm run integration`.

### Quality gates

- `abaplint` strict (already configured) plus a repository dependency gate
  forbidding SAP-standard object usage outside the documented adapters and
  portable kernel-backed exceptions
- CI green = tiers 1+2+3 all pass
- every crypto class lands **with its vectors in the same PR** — no untested crypto

---

## 4. Milestones

Ordered so every milestone ends with something demonstrably working under
`npm test`.

Current completion is tracked below; `CHECKLIST.md` contains the concise view and
the remaining cross-cutting tasks.

### M0 — Foundations (repo mostly has this)
- [x] finish `zcl_oassh_stream`: mpint, byte, fix `boolean_decode`, full testclass
- [x] `zcl_oassh_ascii` (drop `cl_abap_char_utilities`, convert via `cl_abap_codepage`)
- [x] define `zif_oassh_socket`, `zif_oassh_random` + mock/fixed implementations
- [x] restructure `zcl_oassh` to depend only on the interfaces; move APC code to
      `zcl_oassh_socket_apc` (kept compiling on ECC via abaplint target version,
      excluded from transpilation)
- [x] CI runs tier 1 on push

### M1 — Hashing
- [x] `zcl_oassh_sha256` + NIST vectors
- [x] `zcl_oassh_hmac` + RFC 4231 vectors

### M2 — Big integers & key exchange math
- [x] `zcl_oassh_bigint`: add/sub/cmp/mul/mod/modpow + tests
- [x] `zcl_oassh_x25519` + RFC 7748 vectors
- [x] `zcl_oassh_kdf` (exchange hash + key derivation) + captured-session vectors

### M3 — Symmetric crypto
- [x] `zcl_oassh_aes` (FIPS 197 vectors), `zcl_oassh_ctr` (SP 800-38A vectors)

### M4 — Binary packet protocol & full kex  ⭐ first big demo
- [x] `zcl_oassh_packet`: framing, padding rules (§6), MAC, seq numbers
- [x] complete messages 20/21/30/31 (KEXINIT currently echoes the server's list —
      replace with our own algorithm proposal + real random cookie)
- [x] `zcl_oassh_transport` state machine through NEWKEYS
- [x] **Demo: encrypted transport established with real OpenSSH** (tier 3 test:
      handshake completes, server log shows no errors)

### M5 — Host key verification
- [x] `zcl_oassh_rsa` PKCS#1 v1.5 verify + vectors
- [x] verify server signature over exchange hash `H`; known-hosts callback in API

### M6 — Authentication (RFC 4252)
- [x] messages 50–53, `password` method, SERVICE_REQUEST/ACCEPT (5/6)
- [x] tier 3: authenticate against the Docker server

### M7 — Connection layer (RFC 4254)  ⭐ v1.0
- [x] session channel open, window management, `exec` request, stdout/stderr
      collection, exit-status, channel close
- [x] public API: `zcl_oassh=>connect( )->execute( 'uname -a' )`
- [ ] **Demo: run a command on a real server from transpiled ABAP — and from ECC**
      (transpiled and NPL SAP_BASIS 750 APC runs pass; an actual ECC run remains)

### M8 — Hardening & performance
- [x] stream/packet buffers → table-of-xstring to kill O(n²) concat
- [x] rekeying (RFC 4253 §9), IGNORE/DEBUG/UNIMPLEMENTED handling, disconnect codes
- [x] strict-kex (standard + OpenSSH markers, initial-KEX message discipline,
      first-packet enforcement, and directional sequence resets after every NEWKEYS)
- [x] configurable execute/APC timeout with typed error, RFC 4253 payload/wire-size ceilings,
      deterministic malformed/MAC/oversize packet fixtures

### M9 — Nice-to-haves (post-1.0, order by demand)
- [ ] `ssh-ed25519` host keys (needs SHA-512 + edwards arithmetic)
- [ ] `publickey` auth (client-side RSA signing — needs private-key ops + key file parsing)
- [x] `diffie-hellman-group14-sha256` fallback kex (RFC 3526 group 14,
      RFC 8268 peer-value validation and SHA-256 exchange hash; live OpenSSH proof)
- [ ] `chacha20-poly1305@openssh.com`
- [ ] interactive shell channel, `sftp` subsystem, port forwarding

---

## 5. Risks & mitigations

| Risk | Mitigation |
|---|---|
| ABAP has no unsigned 32/64-bit ints; crypto needs wraparound arithmetic | do all word arithmetic on `x`-typed values via the bigint/byte helpers; test vectors catch every mistake |
| Performance: bignum modpow and AES in interpreted ABAP are slow | correctness first; CTR keystream can be precomputed per packet; X25519 is one-shot per connection; measure in M8 |
| 1-byte APC frames on ECC = very slow receive | isolated inside `zcl_oassh_socket_apc`; explore larger frame strategies there without touching protocol code |
| Modern OpenSSH tightened kex (strict kex, algorithm removals) | pin the Docker image version for CI stability; strict-kex in M8; keep tier-2 fixtures so upgrades can't silently break us |
| No secure RNG in pure ABAP | explicitly out of scope to implement one — `zif_oassh_random` is a declared platform dependency, documented as such |
| Timing side channels in pure-ABAP crypto | documented non-goal for v1 (client-side, hobby/integration use); constant-time review is a post-1.0 item |

---

## 6. Definition of done (v1.0)

```abap
DATA(lo_ssh) = zcl_oassh=>connect(
  ii_socket   = lo_socket   " platform implementation
  ii_random   = lo_random
  iv_host     = 'server'
  iv_port     = '22'
  iv_user     = 'user'
  iv_password = 'secret' ).

DATA(lv_output) = lo_ssh->execute( 'echo hello' ).
lo_ssh->close( ).
```

- works identically transpiled on Node (CI-proven against real OpenSSH) and on ECC
- zero SAP-standard dependencies outside `zcl_oassh_socket_apc` + the RNG adapter
- every crypto primitive backed by official test vectors in ABAP Unit
- full recorded-handshake regression test running in plain `npm test`
