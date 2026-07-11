# Transpiler / open-abap anomalies

Behaviours where the `@abaplint` transpiler / open-abap runtime diverge from
standard ABAP (or bit us in a surprising way). Recorded while implementing the
checklist so we can work around them and, where relevant, report upstream.

## `FIND ... IN` treats the pattern as a regular expression

**Found in:** M0 — `zcl_oassh_ascii`

In standard ABAP, `FIND sub IN str` (without the `REGEX` addition) is a literal
substring search. In the transpiler the search pattern is interpreted as a
**regular expression**, so regex metacharacters are not matched literally:

- searching for `$` matched the end-of-string anchor
- searching for `^` matched the start-of-string anchor

This produced wrong offsets when mapping single characters to ASCII codes.

**Workaround:** avoid `FIND` for literal single-character lookups; use an
explicit linear scan comparing `str+i(1)` instead.

## Comparing a length-1 `c` holding a space never matches

**Found in:** M0 — `zcl_oassh_ascii`

Comparing a `c LENGTH 1` variable that contains a space against a one-character
substring that is also a space (`IF str+i(1) = lv_space_char`) evaluates to
**false** in the transpiler. Trailing blanks are trimmed to the empty string on
both operands and the two empties are then treated as unequal. Standard ABAP
would treat `' ' = ' '` as true.

**Workaround:** detect the space via `IF lv_char IS INITIAL` (space is the
initial value of type `c`) rather than by character comparison.

## Arithmetic directly on two `x` operands is rejected

**Found in:** M2 — `zcl_oassh_bigint`

`lt_acc[ i ] = lt_acc[ i ] + byte_a * byte_b`, where `byte_a`/`byte_b` are
`x LENGTH 1`, fails the syntax check with "Incompatible types". Curiously
`byte_a + byte_b + carry` (with an `i` operand in the expression) is accepted.

**Workaround:** assign each `x` byte into an `i` variable first, then do the
multiplication on the integers.

## Comparing two `x` operands with `>` / `<` is signed

**Found in:** M2 — `zcl_oassh_bigint` (surfaced via `zcl_oassh_x25519`)

`IF byte_a > byte_b` on two `x LENGTH 1` values compares them as *signed*, so
`0xFF < 0x7F` evaluates true. This silently broke big-integer `compare` for any
byte >= 0x80 (the bigint tests missed it because they only differed in length).
Note this contrasts with `x`-to-`i` assignment, which is unsigned (`0xFF` -> 255).

**Workaround:** assign both bytes into `i` variables and compare the integers.

## `x`/xstring cannot be written by offset

**Found in:** M2 — `zcl_oassh_x25519`

`lv_xstr+0(1) = lv_byte` (offset/length in a writer position) is rejected for
`xstring`/`string`; reading `lv_xstr+0(1)` is fine.

**Workaround:** rebuild the string with `CONCATENATE ... IN BYTE MODE` around
the byte being changed.

## Runtime `XString.set()` does not normalize lowercase hexadecimal text

**Found in:** M4 — Node TCP integration adapter

Passing Node's default lowercase `Buffer.toString('hex')` result to
`new abap.types.XString().set(...)` preserves the lowercase representation.
Byte comparisons against ABAP hexadecimal literals are then case-sensitive, so
the incoming `0d0a` SSH version terminator did not compare equal to the ABAP
constant `0D0A` even though both represent the same bytes.

**Workaround:** uppercase hexadecimal strings at every handwritten JavaScript
boundary before assigning them to an open-abap `XString`.

## `RETURN` inside a loop nested in a later CASE/IF branch: `indexBackup1 is not defined`

**Found in:** M6 — `zcl_oassh` receive state machine

The transpiler saves/restores `sy-index` around each loop with a per-loop
`const indexBackupN`, declared **inside that branch's block**. But a `RETURN`
statement inside a loop always emits the restore against `indexBackup1`
regardless of which loop it is in. When the loop lives in the second or later
branch of a `CASE`/`IF` (where `indexBackup1` is out of scope), the generated
JavaScript throws `ReferenceError: indexBackup1 is not defined` — but only when
that `RETURN` line is actually reached at runtime, so it hides until exercised.

```abap
CASE mv_state.
  WHEN 1. WHILE cond. ... RETURN. ... ENDWHILE.   " indexBackup1 in scope, ok
  WHEN 2. WHILE cond. ... RETURN. ... ENDWHILE.   " restores indexBackup1 -> crash
ENDCASE.
```

**Workaround:** keep at most one loop per method and don't nest loops-with-RETURN
inside `CASE`/`IF` branches. Splitting each state's handling into its own method
puts every loop at the method top level, so its `indexBackup1` is always in
scope. (We don't rely on `sy-index` here, so the mis-numbered restore value
itself is harmless once it resolves.)

## Method calls in `WAIT UNTIL` generate invalid JavaScript

**Found in:** M7 — synchronous `execute( )` facade over socket callbacks

A condition such as `WAIT UNTIL mo_channel->get_state( ) = closed` is emitted
as a non-async JavaScript arrow callback containing `await`. Node rejects the
generated module at parse time with `SyntaxError: Unexpected reserved word`.

**Workaround:** have the callback path copy completion into a plain boolean
attribute and make the wait condition compare only that attribute.

## `CONCATENATE LINES OF ... IN BYTE MODE` is not byte-safe

**Found in:** M8 — `zcl_oassh_stream` buffer rework

The open-abap runtime `concatenate` implementation has no byte-mode branch: for
the `LINES OF` form it calls `line.get().trimEnd()` on every row and joins the
results with character semantics, then `set()`s the target. For an `xstring`
table this happens to round-trip the hex text in simple cases, but it applies
character trimming and offers no guarantee the join is treated as bytes — it is
the character code path regardless of the `IN BYTE MODE` addition.

**Workaround:** do not use `CONCATENATE LINES OF it INTO x IN BYTE MODE` to
join an `xstring` table. Fold the chunks with the byte concat operator in a
loop (`x = x && chunk`) — each `&&` on `xstring` is a real byte concatenation
in the runtime (`XString.set` over the hex representation). Two-operand
`CONCATENATE a b INTO c IN BYTE MODE` is fine; only the `LINES OF` table form is
affected.

## Transpiled `WAIT UNTIL ... UP TO` ignores the timeout

**Found in:** M7 — synchronous `execute( )` facade over socket callbacks

The transpiler passes the timeout to `abap.statements.wait`, but open-abap's
runtime wait implementation never examines it. It polls until the condition is
true, so `UP TO 300 SECONDS` does not time out as it does on standard ABAP.

**Workaround:** successful protocol completion remains the condition. A proper
portable timeout must be implemented above the runtime when timeout handling is
added in M8.
