CLASS zcl_oassh_ctr DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    METHODS constructor
      IMPORTING
        iv_key     TYPE xstring
        iv_counter TYPE xstring.
    METHODS crypt
      IMPORTING
        iv_data        TYPE xstring
      RETURNING
        VALUE(rv_data) TYPE xstring.

  PRIVATE SECTION.
    DATA mv_key       TYPE xstring.
    DATA mv_counter   TYPE xstring.
    DATA mv_keystream TYPE xstring.
    DATA mv_offset    TYPE i VALUE 16.

    METHODS increment_counter.
ENDCLASS.


CLASS zcl_oassh_ctr IMPLEMENTATION.

  METHOD constructor.
    mv_key = iv_key.
    mv_counter = iv_counter.
  ENDMETHOD.


  METHOD increment_counter.
* Treat the 128-bit counter as an unsigned big-endian integer.
    DATA lv_pos    TYPE i VALUE 15.
    DATA lv_value  TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.
    DATA lv_prefix TYPE xstring.
    DATA lv_suffix TYPE xstring.
    DATA lv_length TYPE i.
    DATA lv_start  TYPE i.

    WHILE lv_pos >= 0.
      lv_byte = mv_counter+lv_pos(1).
      lv_value = lv_byte.
      IF lv_value = 255.
        lv_byte = 0.
      ELSE.
        lv_value = lv_value + 1.
        lv_byte = lv_value.
      ENDIF.

      CLEAR: lv_prefix, lv_suffix.
      IF lv_pos > 0.
        lv_prefix = mv_counter(lv_pos).
      ENDIF.
      lv_length = 15 - lv_pos.
      IF lv_length > 0.
        lv_start = lv_pos + 1.
        lv_suffix = mv_counter+lv_start(lv_length).
      ENDIF.
      CONCATENATE lv_prefix lv_byte lv_suffix
        INTO mv_counter IN BYTE MODE.

      IF lv_byte <> 0.
        RETURN.
      ENDIF.
      lv_pos = lv_pos - 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD crypt.
    DATA lv_pos TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_key_byte TYPE x LENGTH 1.
    DATA lv_result TYPE x LENGTH 1.
    DATA lv_length TYPE i.

    lv_length = xstrlen( iv_data ).
    WHILE lv_pos < lv_length.
      IF mv_offset >= 16.
        mv_keystream = zcl_oassh_aes=>encrypt_block(
          iv_key   = mv_key
          iv_block = mv_counter ).
        increment_counter( ).
        mv_offset = 0.
      ENDIF.

      lv_byte = iv_data+lv_pos(1).
      lv_key_byte = mv_keystream+mv_offset(1).
      lv_result = lv_byte BIT-XOR lv_key_byte.
      CONCATENATE rv_data lv_result INTO rv_data IN BYTE MODE.
      lv_pos = lv_pos + 1.
      mv_offset = mv_offset + 1.
    ENDWHILE.
  ENDMETHOD.

ENDCLASS.
