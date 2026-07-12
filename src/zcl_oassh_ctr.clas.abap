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
* The AES key schedule is expanded once in the constructor and reused for
* every counter block. mv_keystream holds keystream bytes generated but not
* yet consumed, so a split call stream stays byte-for-byte identical.
    DATA mt_schedule  TYPE zcl_oassh_aes=>ty_words.
    DATA mv_counter   TYPE x LENGTH 16.
    DATA mv_keystream TYPE xstring.

    METHODS increment_counter.
ENDCLASS.


CLASS zcl_oassh_ctr IMPLEMENTATION.

  METHOD constructor.
    mt_schedule = zcl_oassh_aes=>expand_key( iv_key ).
    mv_counter = iv_counter.
  ENDMETHOD.


  METHOD increment_counter.
* Treat the 128-bit counter as an unsigned big-endian integer.
    DATA lv_pos   TYPE i VALUE 15.
    DATA lv_value TYPE i.
    DATA lv_byte  TYPE x LENGTH 1.

    WHILE lv_pos >= 0.
      lv_byte = mv_counter+lv_pos(1).
      lv_value = lv_byte.
      IF lv_value = 255.
        lv_byte = '00'.
        mv_counter+lv_pos(1) = lv_byte.
        lv_pos = lv_pos - 1.
      ELSE.
        lv_value = lv_value + 1.
        lv_byte = lv_value.
        mv_counter+lv_pos(1) = lv_byte.
        RETURN.
      ENDIF.
    ENDWHILE.
  ENDMETHOD.


  METHOD crypt.
* XOR the data against the counter keystream a whole block at a time. The
* keystream blocks are folded into a single xstring so the final XOR is one
* linear operation rather than one CONCATENATE per byte (was O(n^2)).
    DATA lv_length  TYPE i.
    DATA lv_have     TYPE i.
    DATA lv_counter  TYPE xstring.
    DATA lv_block    TYPE xstring.
    DATA lv_ks       TYPE xstring.
    DATA lv_used     TYPE xstring.
    DATA lt_blocks   TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.

    lv_length = xstrlen( iv_data ).
    IF lv_length = 0.
      RETURN.
    ENDIF.

    IF mv_keystream IS NOT INITIAL.
      APPEND mv_keystream TO lt_blocks.
    ENDIF.
    lv_have = xstrlen( mv_keystream ).
    WHILE lv_have < lv_length.
      lv_counter = mv_counter.
      lv_block = zcl_oassh_aes=>encrypt_block_schedule(
        it_w     = mt_schedule
        iv_block = lv_counter ).
      increment_counter( ).
      APPEND lv_block TO lt_blocks.
      lv_have = lv_have + 16.
    ENDWHILE.
    CONCATENATE LINES OF lt_blocks INTO lv_ks IN BYTE MODE.

    lv_used = lv_ks(lv_length).
    rv_data = iv_data BIT-XOR lv_used.
    mv_keystream = lv_ks+lv_length.
  ENDMETHOD.

ENDCLASS.
