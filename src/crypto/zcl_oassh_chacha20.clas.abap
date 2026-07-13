CLASS zcl_oassh_chacha20 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* ChaCha20 core (RFC 8439) plus OpenSSH's original 64-bit-counter,
* 64-bit-nonce layout. Words are kept big-endian internally so unsigned
* addition can be implemented bytewise on every supported ABAP runtime.
    CLASS-METHODS block_ietf
      IMPORTING
        iv_key     TYPE xstring
        iv_counter TYPE i
        iv_nonce   TYPE xstring
      RETURNING VALUE(rv_block) TYPE xstring.
    CLASS-METHODS block_ssh
      IMPORTING
        iv_key     TYPE xstring
        iv_counter TYPE i
        iv_nonce   TYPE xstring
      RETURNING VALUE(rv_block) TYPE xstring.
    CLASS-METHODS crypt_ssh
      IMPORTING
        iv_key     TYPE xstring
        iv_nonce   TYPE xstring
        iv_counter TYPE i
        iv_data    TYPE xstring
      RETURNING VALUE(rv_data) TYPE xstring.
  PRIVATE SECTION.
    TYPES ty_word TYPE x LENGTH 4.
    TYPES ty_words TYPE STANDARD TABLE OF ty_word WITH EMPTY KEY.
    CLASS-METHODS add_word
      IMPORTING
        iv_a TYPE ty_word
        iv_b TYPE ty_word
      RETURNING VALUE(rv_word) TYPE ty_word.
    CLASS-METHODS reverse_word
      IMPORTING iv_word TYPE ty_word
      RETURNING VALUE(rv_word) TYPE ty_word.
    CLASS-METHODS rotate_left
      IMPORTING
        iv_word TYPE ty_word
        iv_bits TYPE i
      RETURNING VALUE(rv_word) TYPE ty_word.
    CLASS-METHODS quarter_round
      IMPORTING
        iv_a TYPE i
        iv_b TYPE i
        iv_c TYPE i
        iv_d TYPE i
      CHANGING ct_state TYPE ty_words.
    CLASS-METHODS rounds
      IMPORTING it_initial TYPE ty_words
      RETURNING VALUE(rv_block) TYPE xstring.
ENDCLASS.


CLASS zcl_oassh_chacha20 IMPLEMENTATION.
  METHOD add_word.
    DATA lv_offset TYPE i.
    DATA lv_a TYPE x LENGTH 1.
    DATA lv_b TYPE x LENGTH 1.
    DATA lv_out TYPE x LENGTH 1.
    DATA lv_sum TYPE i.
    DATA lv_carry TYPE i.
    DO 4 TIMES.
      lv_offset = 4 - sy-index.
      lv_a = iv_a+lv_offset(1).
      lv_b = iv_b+lv_offset(1).
      lv_sum = lv_a + lv_b + lv_carry.
      lv_out = lv_sum MOD 256.
      lv_carry = lv_sum DIV 256.
      CONCATENATE lv_out rv_word INTO rv_word IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD reverse_word.
    CONCATENATE iv_word+3(1) iv_word+2(1) iv_word+1(1) iv_word(1)
      INTO rv_word IN BYTE MODE.
  ENDMETHOD.


  METHOD rotate_left.
    DATA lv_byte_shift TYPE i.
    DATA lv_bits TYPE i.
    DATA lv_index TYPE i.
    DATA lv_source TYPE i.
    DATA lv_next TYPE i.
    DATA lv_factor TYPE i VALUE 1.
    DATA lv_divisor TYPE i VALUE 1.
    DATA lv_current_byte TYPE x LENGTH 1.
    DATA lv_next_byte TYPE x LENGTH 1.
    DATA lv_out TYPE x LENGTH 1.
    DATA lv_shifted TYPE ty_word.

    lv_byte_shift = iv_bits DIV 8.
    lv_bits = iv_bits MOD 8.
    DO 4 TIMES.
      lv_index = sy-index - 1.
      lv_source = ( lv_index + lv_byte_shift ) MOD 4.
      lv_shifted+lv_index(1) = iv_word+lv_source(1).
    ENDDO.
    IF lv_bits = 0.
      rv_word = lv_shifted.
      RETURN.
    ENDIF.
    DO lv_bits TIMES.
      lv_factor = lv_factor * 2.
    ENDDO.
    DO 8 - lv_bits TIMES.
      lv_divisor = lv_divisor * 2.
    ENDDO.
    DO 4 TIMES.
      lv_index = sy-index - 1.
      lv_next = ( lv_index + 1 ) MOD 4.
      lv_current_byte = lv_shifted+lv_index(1).
      lv_next_byte = lv_shifted+lv_next(1).
      lv_out = ( lv_current_byte * lv_factor ) MOD 256
        + lv_next_byte DIV lv_divisor.
      rv_word+lv_index(1) = lv_out.
    ENDDO.
  ENDMETHOD.


  METHOD quarter_round.
    DATA lv_a TYPE ty_word.
    DATA lv_b TYPE ty_word.
    DATA lv_c TYPE ty_word.
    DATA lv_d TYPE ty_word.
    lv_a = ct_state[ iv_a ].
    lv_b = ct_state[ iv_b ].
    lv_c = ct_state[ iv_c ].
    lv_d = ct_state[ iv_d ].

    lv_a = add_word(
      iv_a = lv_a
      iv_b = lv_b ).
    lv_d = rotate_left(
      iv_word = lv_d BIT-XOR lv_a
      iv_bits = 16 ).
    lv_c = add_word(
      iv_a = lv_c
      iv_b = lv_d ).
    lv_b = rotate_left(
      iv_word = lv_b BIT-XOR lv_c
      iv_bits = 12 ).
    lv_a = add_word(
      iv_a = lv_a
      iv_b = lv_b ).
    lv_d = rotate_left(
      iv_word = lv_d BIT-XOR lv_a
      iv_bits = 8 ).
    lv_c = add_word(
      iv_a = lv_c
      iv_b = lv_d ).
    lv_b = rotate_left(
      iv_word = lv_b BIT-XOR lv_c
      iv_bits = 7 ).

    ct_state[ iv_a ] = lv_a.
    ct_state[ iv_b ] = lv_b.
    ct_state[ iv_c ] = lv_c.
    ct_state[ iv_d ] = lv_d.
  ENDMETHOD.


  METHOD rounds.
    DATA lt_state TYPE ty_words.
    DATA lv_word TYPE ty_word.
    lt_state = it_initial.
    DO 10 TIMES.
      quarter_round(
        EXPORTING
          iv_a            = 1
          iv_b            = 5
          iv_c            = 9
          iv_d            = 13
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 2
          iv_b            = 6
          iv_c            = 10
          iv_d            = 14
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 3
          iv_b            = 7
          iv_c            = 11
          iv_d            = 15
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 4
          iv_b            = 8
          iv_c            = 12
          iv_d            = 16
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 1
          iv_b            = 6
          iv_c            = 11
          iv_d            = 16
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 2
          iv_b            = 7
          iv_c            = 12
          iv_d            = 13
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 3
          iv_b            = 8
          iv_c            = 9
          iv_d            = 14
        CHANGING ct_state = lt_state ).
      quarter_round(
        EXPORTING
          iv_a            = 4
          iv_b            = 5
          iv_c            = 10
          iv_d            = 15
        CHANGING ct_state = lt_state ).
    ENDDO.
    DO 16 TIMES.
      lv_word = add_word(
        iv_a = lt_state[ sy-index ]
        iv_b = it_initial[ sy-index ] ).
      lv_word = reverse_word( lv_word ).
      CONCATENATE rv_block lv_word INTO rv_block IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD block_ietf.
    DATA lt_state TYPE ty_words.
    DATA lv_offset TYPE i.
    DATA lv_word TYPE ty_word.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ASSERT xstrlen( iv_key ) = 32.
    ASSERT xstrlen( iv_nonce ) = 12.
    APPEND '61707865' TO lt_state.
    APPEND '3320646E' TO lt_state.
    APPEND '79622D32' TO lt_state.
    APPEND '6B206574' TO lt_state.
    DO 8 TIMES.
      lv_offset = ( sy-index - 1 ) * 4.
      lv_word = iv_key+lv_offset(4).
      APPEND reverse_word( lv_word ) TO lt_state.
    ENDDO.
    lo_stream = NEW #( ).
    lo_stream->uint32_encode( iv_counter ).
    APPEND lo_stream->get( ) TO lt_state.
    DO 3 TIMES.
      lv_offset = ( sy-index - 1 ) * 4.
      lv_word = iv_nonce+lv_offset(4).
      APPEND reverse_word( lv_word ) TO lt_state.
    ENDDO.
    rv_block = rounds( lt_state ).
  ENDMETHOD.


  METHOD block_ssh.
    DATA lt_state TYPE ty_words.
    DATA lv_offset TYPE i.
    DATA lv_word TYPE ty_word.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ASSERT xstrlen( iv_key ) = 32.
    ASSERT xstrlen( iv_nonce ) = 8.
    APPEND '61707865' TO lt_state.
    APPEND '3320646E' TO lt_state.
    APPEND '79622D32' TO lt_state.
    APPEND '6B206574' TO lt_state.
    DO 8 TIMES.
      lv_offset = ( sy-index - 1 ) * 4.
      lv_word = iv_key+lv_offset(4).
      APPEND reverse_word( lv_word ) TO lt_state.
    ENDDO.
    lo_stream = NEW #( ).
    lo_stream->uint32_encode( iv_counter ).
    APPEND lo_stream->get( ) TO lt_state.
    APPEND '00000000' TO lt_state.
    lv_word = iv_nonce(4).
    APPEND reverse_word( lv_word ) TO lt_state.
    lv_word = iv_nonce+4(4).
    APPEND reverse_word( lv_word ) TO lt_state.
    rv_block = rounds( lt_state ).
  ENDMETHOD.


  METHOD crypt_ssh.
    DATA lv_offset TYPE i.
    DATA lv_length TYPE i.
    DATA lv_counter TYPE i.
    DATA lv_block TYPE xstring.
    DATA lv_data TYPE xstring.
    DATA lv_result TYPE xstring.
    DATA lo_output TYPE REF TO zcl_oassh_stream.
    lv_counter = iv_counter.
    lo_output = NEW #( ).
    WHILE xstrlen( iv_data ) > lv_offset.
      lv_length = xstrlen( iv_data ) - lv_offset.
      IF lv_length > 64.
        lv_length = 64.
      ENDIF.
      lv_block = block_ssh(
        iv_key     = iv_key
        iv_counter = lv_counter
        iv_nonce   = iv_nonce ).
      lv_data = iv_data+lv_offset(lv_length).
      lv_result = lv_data BIT-XOR lv_block(lv_length).
      lo_output->append( lv_result ).
      lv_offset = lv_offset + lv_length.
      lv_counter = lv_counter + 1.
    ENDWHILE.
    rv_data = lo_output->get( ).
  ENDMETHOD.
ENDCLASS.
