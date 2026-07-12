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

    DATA lv_offset TYPE i.
    DATA lv_length TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.

    lv_length = xstrlen( mv_pattern ).
    ASSERT lv_length > 0.

    DO iv_length TIMES.
      lv_offset = ( sy-index - 1 ) MOD lv_length.
      lv_byte = mv_pattern+lv_offset(1).
      rv_hex = rv_hex && lv_byte.
    ENDDO.

  ENDMETHOD.
ENDCLASS.
