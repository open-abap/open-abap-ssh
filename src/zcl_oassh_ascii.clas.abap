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
ENDCLASS.



CLASS zcl_oassh_ascii IMPLEMENTATION.


  METHOD from_xstring_text.
* Command output is text rather than an SSH identifier, so retain the common
* ASCII whitespace controls that from_xstring intentionally drops.
    DATA lv_offset   TYPE i.
    DATA lv_byte     TYPE x LENGTH 1.
    DATA lv_code     TYPE i.
    DATA lv_filtered TYPE xstring.

    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF lv_code = 9 OR lv_code = 10 OR lv_code = 13
          OR ( lv_code >= 32 AND lv_code <= 126 ).
        CONCATENATE lv_filtered lv_byte INTO lv_filtered IN BYTE MODE.
      ENDIF.
    ENDDO.

    rv_string = cl_abap_codepage=>convert_from( lv_filtered ).

  ENDMETHOD.


  METHOD from_xstring.

    DATA lv_offset   TYPE i.
    DATA lv_byte     TYPE x LENGTH 1.
    DATA lv_code     TYPE i.
    DATA lv_filtered TYPE xstring.

* non-printable bytes (e.g. the trailing CR LF) are dropped
    DO xstrlen( iv_hex ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF lv_code >= 32 AND lv_code <= 126.
        CONCATENATE lv_filtered lv_byte INTO lv_filtered IN BYTE MODE.
      ENDIF.
    ENDDO.

    rv_string = cl_abap_codepage=>convert_from( lv_filtered ).

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
