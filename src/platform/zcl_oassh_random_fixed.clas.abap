CLASS zcl_oassh_random_fixed DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* deterministic zif_oassh_random for tests: repeats a fixed byte pattern,
* so exchange hashes and cookies are reproducible.

    INTERFACES zif_oassh_random.

    METHODS constructor
      IMPORTING
        iv_pattern TYPE xstring OPTIONAL.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mv_pattern TYPE xstring.
* cache of the repeated pattern, grown by doubling and reused across calls
    DATA mv_buffer  TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_random_fixed IMPLEMENTATION.


  METHOD constructor.

    IF iv_pattern IS INITIAL.
* an arbitrary but recognisable default pattern
      mv_pattern = 'AB'.
    ELSE.
      mv_pattern = iv_pattern.
    ENDIF.

  ENDMETHOD.


  METHOD zif_oassh_random~bytes.

* bytes( n ) is the first n bytes of the endlessly repeated pattern, so the
* repeated pattern is cached and grown by doubling: log2( n ) concatenations
* instead of n, and repeated calls reuse the buffer. Slicing stays correct
* because the buffer length is always a multiple of the pattern length.
    IF iv_length = 0.
      RETURN.
    ENDIF.

    ASSERT xstrlen( mv_pattern ) > 0.

    IF xstrlen( mv_buffer ) = 0.
      mv_buffer = mv_pattern.
    ENDIF.

    WHILE xstrlen( mv_buffer ) < iv_length.
      mv_buffer = mv_buffer && mv_buffer.
    ENDWHILE.

    rv_hex = mv_buffer(iv_length).

  ENDMETHOD.
ENDCLASS.
