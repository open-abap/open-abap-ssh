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
