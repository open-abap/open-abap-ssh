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

    TYPES ty_blocks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.

    METHODS increment_counter.
    CLASS-METHODS join_blocks
      IMPORTING
        it_blocks      TYPE ty_blocks
      RETURNING
        VALUE(rv_data) TYPE xstring.
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


  METHOD join_blocks.
* CONCATENATE LINES OF xstring uses the character path in open-abap (see
* ANORMALIES.md). Pairwise byte concatenation is portable and limits each
* generated block to logarithmically many copies.
    DATA lt_current TYPE ty_blocks.
    DATA lt_next TYPE ty_blocks.
    DATA lv_index TYPE i.
    DATA lv_count TYPE i.
    DATA lv_joined TYPE xstring.
    lt_current = it_blocks.
    WHILE lines( lt_current ) > 1.
      CLEAR lt_next.
      lv_index = 1.
      lv_count = lines( lt_current ).
      WHILE lv_index <= lv_count.
        IF lv_index = lv_count.
          APPEND lt_current[ lv_index ] TO lt_next.
        ELSE.
          DATA(lv_left) = lt_current[ lv_index ].
          DATA(lv_right) = lt_current[ lv_index + 1 ].
          CONCATENATE lv_left lv_right
            INTO lv_joined IN BYTE MODE.
          APPEND lv_joined TO lt_next.
        ENDIF.
        lv_index = lv_index + 2.
      ENDWHILE.
      lt_current = lt_next.
    ENDWHILE.
    IF lt_current IS NOT INITIAL.
      rv_data = lt_current[ 1 ].
    ENDIF.
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
    DATA lt_blocks   TYPE ty_blocks.

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
    lv_ks = join_blocks( lt_blocks ).

    lv_used = lv_ks(lv_length).
    rv_data = iv_data BIT-XOR lv_used.
    mv_keystream = lv_ks+lv_length.
  ENDMETHOD.

ENDCLASS.
