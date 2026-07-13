CLASS zcl_oassh_ascii DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* SSH protocol text (version string, name-lists) is 7-bit US-ASCII,
* see https://datatracker.ietf.org/doc/html/rfc4251 . Conversion is
* delegated to cl_abap_codepage, one of the allowed standard classes
* (see PLAN.md); ASCII is a subset of its UTF-8 default. This class adds
* the SSH-specific filtering of non-printable bytes.

    CONSTANTS c_cr_lf TYPE x LENGTH 2 VALUE '0D0A'.

    CLASS-METHODS to_xstring
      IMPORTING
        iv_string     TYPE string
      RETURNING
        VALUE(rv_hex) TYPE xstring.
    CLASS-METHODS to_xstring_text
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
    TYPES ty_chunks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    CLASS-METHODS filter_bytes
      IMPORTING
        iv_hex                TYPE xstring
        iv_keep_text_controls TYPE abap_bool
      RETURNING
        VALUE(rv_filtered)    TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_ascii IMPLEMENTATION.


  METHOD to_xstring_text.
* RFC-defined application text is UTF-8 and may contain non-ASCII characters.
    rv_hex = cl_abap_codepage=>convert_to( iv_string ).
  ENDMETHOD.


  METHOD from_xstring_text.
* Command output is text rather than an SSH identifier, so retain the common
* ASCII whitespace controls that from_xstring intentionally drops, and retain
* UTF-8 multibyte bytes used by internationalized command output.
    DATA lv_offset   TYPE i.
    DATA lv_byte     TYPE x LENGTH 1.
    DATA lv_code     TYPE i.
    DATA lv_all_valid TYPE abap_bool VALUE abap_true.

* Command output is normally already valid text. Validate once and hand the
* original xstring directly to the codepage converter, avoiding one growing
* byte concatenation per output character.
    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF lv_code <> 9 AND lv_code <> 10 AND lv_code <> 13
          AND ( lv_code < 32 OR lv_code = 127 ).
        lv_all_valid = abap_false.
        EXIT.
      ENDIF.
    ENDDO.
    IF lv_all_valid = abap_true.
      rv_string = cl_abap_codepage=>convert_from( iv_hex ).
      RETURN.
    ENDIF.

    rv_string = cl_abap_codepage=>convert_from( filter_bytes(
      iv_hex                = iv_hex
      iv_keep_text_controls = abap_true ) ).

  ENDMETHOD.


  METHOD from_xstring.

    DATA lv_offset   TYPE i.
    DATA lv_byte     TYPE x LENGTH 1.
    DATA lv_code     TYPE i.
    DATA lv_all_valid TYPE abap_bool VALUE abap_true.

* non-printable bytes (e.g. the trailing CR LF) are dropped
* Valid SSH text is the common path. Avoid rebuilding a growing xstring one
* byte at a time, which is quadratic for long peer-provided name-lists and
* banners.
    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF lv_code < 32 OR lv_code > 126.
        lv_all_valid = abap_false.
        EXIT.
      ENDIF.
    ENDDO.
    IF lv_all_valid = abap_true.
      rv_string = cl_abap_codepage=>convert_from( iv_hex ).
      RETURN.
    ENDIF.

    rv_string = cl_abap_codepage=>convert_from( filter_bytes(
      iv_hex                = iv_hex
      iv_keep_text_controls = abap_false ) ).

  ENDMETHOD.


  METHOD filter_bytes.
* Collect maximal valid runs and join them pairwise. A hostile alternating
* valid/control byte stream therefore never repeatedly copies its full prefix.
    DATA lt_current TYPE ty_chunks.
    DATA lt_next TYPE ty_chunks.
    DATA lv_offset TYPE i.
    DATA lv_run_start TYPE i.
    DATA lv_run_length TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_code TYPE i.
    DATA lv_valid TYPE abap_bool.
    DATA lv_chunk TYPE xstring.
    DATA lv_joined TYPE xstring.
    DATA lv_index TYPE i.
    DATA lv_count TYPE i.
    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF iv_keep_text_controls = abap_true.
        lv_valid = xsdbool( lv_code = 9 OR lv_code = 10 OR lv_code = 13
          OR ( lv_code >= 32 AND lv_code <> 127 ) ).
      ELSE.
        lv_valid = xsdbool( lv_code >= 32 AND lv_code <= 126 ).
      ENDIF.
      IF lv_valid = abap_false.
        lv_run_length = lv_offset - lv_run_start.
        IF lv_run_length > 0.
          lv_chunk = iv_hex+lv_run_start(lv_run_length).
          APPEND lv_chunk TO lt_current.
        ENDIF.
        lv_run_start = lv_offset + 1.
      ENDIF.
    ENDDO.
    lv_run_length = xstrlen( iv_hex ) - lv_run_start.
    IF lv_run_length > 0.
      lv_chunk = iv_hex+lv_run_start(lv_run_length).
      APPEND lv_chunk TO lt_current.
    ENDIF.
    WHILE lines( lt_current ) > 1.
      CLEAR lt_next.
      lv_index = 1.
      lv_count = lines( lt_current ).
      WHILE lv_index <= lv_count.
        IF lv_index = lv_count.
          APPEND lt_current[ lv_index ] TO lt_next.
        ELSE.
          CONCATENATE lt_current[ lv_index ] lt_current[ lv_index + 1 ]
            INTO lv_joined IN BYTE MODE.
          APPEND lv_joined TO lt_next.
        ENDIF.
        lv_index = lv_index + 2.
      ENDWHILE.
      lt_current = lt_next.
    ENDWHILE.
    IF lt_current IS NOT INITIAL.
      rv_filtered = lt_current[ 1 ].
    ENDIF.
  ENDMETHOD.


  METHOD to_xstring.

    DATA lv_offset TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.
    DATA lv_code   TYPE i.

    rv_hex = cl_abap_codepage=>convert_to( iv_string ).

* only 7-bit ASCII is supported: any byte >= 0x80 means the input held a
* character that UTF-8 encoded as a multi-byte sequence
    DO xstrlen( rv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = rv_hex+lv_offset(1).
      lv_code = lv_byte.
      ASSERT lv_code < 128.
    ENDDO.

  ENDMETHOD.
ENDCLASS.
