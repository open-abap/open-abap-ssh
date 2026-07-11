CLASS zcl_oassh_ascii DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* SSH protocol text (version string, name-lists) is 7-bit US-ASCII,
* see https://datatracker.ietf.org/doc/html/rfc4251 . This class replaces
* cl_abap_codepage / cl_abap_char_utilities so the core has no dependency
* on SAP standard classes.

    CONSTANTS c_cr_lf TYPE x LENGTH 2 VALUE '0D0A'.

    CLASS-METHODS to_xstring
      IMPORTING
        iv_string     TYPE string
      RETURNING
        VALUE(rv_hex) TYPE xstring.
    CLASS-METHODS from_xstring
      IMPORTING
        iv_hex           TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string.
    CLASS-METHODS from_xstring_text
      IMPORTING
        iv_hex           TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string.
  PROTECTED SECTION.
  PRIVATE SECTION.

* offset N of this string holds the character with ASCII code N + 32,
* covering the printable range 32 (space) to 126 (tilde)
    CLASS-METHODS printable
      RETURNING
        VALUE(rv_printable) TYPE string.
ENDCLASS.



CLASS zcl_oassh_ascii IMPLEMENTATION.


  METHOD from_xstring_text.
* Command output is text rather than an SSH identifier, so retain the common
* ASCII whitespace controls that from_xstring intentionally drops.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_code TYPE i.
    DATA lv_index TYPE i.
    DATA lv_printable TYPE string.
    lv_printable = printable( ).
    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      CASE lv_code.
        WHEN 9.
          rv_string = rv_string && |\t|.
        WHEN 10.
          rv_string = rv_string && |\n|.
        WHEN 13.
          rv_string = rv_string && |\r|.
        WHEN OTHERS.
          IF lv_code >= 32 AND lv_code <= 126.
            lv_index = lv_code - 32.
            rv_string = rv_string && lv_printable+lv_index(1).
          ENDIF.
      ENDCASE.
    ENDDO.
  ENDMETHOD.


  METHOD from_xstring.

    DATA lv_offset    TYPE i.
    DATA lv_byte      TYPE x LENGTH 1.
    DATA lv_code      TYPE i.
    DATA lv_index     TYPE i.
    DATA lv_printable TYPE string.

    lv_printable = printable( ).

    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
* non-printable bytes (e.g. the trailing CR LF) are dropped
      IF lv_code >= 32 AND lv_code <= 126.
        lv_index = lv_code - 32.
        rv_string = rv_string && lv_printable+lv_index(1).
      ENDIF.
    ENDDO.

  ENDMETHOD.


  METHOD printable.

    rv_printable =
      ` !"#$%&'()*+,-./0123456789:;<=>?@` &&
      `ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` &&
      ```abcdefghijklmnopqrstuvwxyz{|}~`.

  ENDMETHOD.


  METHOD to_xstring.

    DATA lv_offset    TYPE i.
    DATA lv_char      TYPE c LENGTH 1.
    DATA lv_pos       TYPE i.
    DATA lv_byte      TYPE x LENGTH 1.
    DATA lv_found     TYPE abap_bool.
    DATA lv_printable TYPE string.

    lv_printable = printable( ).

* a linear scan is used instead of FIND, as the transpiler treats the
* FIND search pattern as a regular expression (see ANORMALIES.md)
    DO strlen( iv_string ) TIMES.
      lv_offset = sy-index - 1.
      lv_char = iv_string+lv_offset(1).
* a space (initial value of type c) cannot be matched by comparison, as
* the transpiler trims trailing blanks (see ANORMALIES.md)
      IF lv_char IS INITIAL.
        lv_byte = 32.
        rv_hex = rv_hex && lv_byte.
        CONTINUE.
      ENDIF.
      lv_found = abap_false.
      DO strlen( lv_printable ) TIMES.
        lv_pos = sy-index - 1.
        IF lv_printable+lv_pos(1) = lv_char.
          lv_byte = lv_pos + 32.
          rv_hex = rv_hex && lv_byte.
          lv_found = abap_true.
          EXIT.
        ENDIF.
      ENDDO.
* only printable 7-bit ASCII is supported
      ASSERT lv_found = abap_true.
    ENDDO.

  ENDMETHOD.
ENDCLASS.
