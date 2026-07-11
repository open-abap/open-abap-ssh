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
