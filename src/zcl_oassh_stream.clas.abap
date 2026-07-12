CLASS zcl_oassh_stream DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES ty_byte TYPE x LENGTH 1.

    METHODS constructor
      IMPORTING
        iv_hex TYPE xstring OPTIONAL.
    METHODS get
      RETURNING
        VALUE(rv_hex) TYPE xstring.
    METHODS take
      IMPORTING
        iv_length    TYPE i
      RETURNING
        VALUE(rv_hex) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS append
      IMPORTING
        iv_hex TYPE xsequence.
    METHODS name_list_encode
      IMPORTING
        it_list TYPE string_table.
    METHODS boolean_encode
      IMPORTING
        iv_boolean TYPE abap_bool.
    METHODS boolean_decode
      RETURNING
        VALUE(rv_boolean) TYPE abap_bool
      RAISING
        zcx_oassh_error.
    METHODS byte_encode
      IMPORTING
        iv_byte TYPE x.
    METHODS byte_decode
      RETURNING
        VALUE(rv_byte) TYPE ty_byte
      RAISING
        zcx_oassh_error.
    METHODS mpint_encode
      IMPORTING
        iv_int TYPE xsequence.
    METHODS mpint_decode
      RETURNING
        VALUE(rv_int) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS mpint_decode_positive
      RETURNING
        VALUE(rv_int) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS name_list_decode
      RETURNING
        VALUE(rt_list) TYPE string_table
      RAISING
        zcx_oassh_error.
    METHODS uint32_encode
      IMPORTING
        iv_int TYPE i.
    METHODS uint32_decode
      RETURNING
        VALUE(rv_int) TYPE i
      RAISING
        zcx_oassh_error.
    METHODS uint32_decode_peek
      RETURNING
        VALUE(rv_int) TYPE i
      RAISING
        zcx_oassh_error.
    METHODS get_length
      RETURNING
        VALUE(rv_length) TYPE i.
    METHODS clear.
    METHODS string_encode
      IMPORTING
        iv_string TYPE xstring.
    METHODS string_decode
      RETURNING
        VALUE(rv_string) TYPE xstring
      RAISING
        zcx_oassh_error.
  PROTECTED SECTION.
  PRIVATE SECTION.

* Read side: mv_hex holds the backing bytes, mv_pos is the read cursor.
* take/decode advance mv_pos instead of re-slicing the buffer (was O(n^2)).
* Write side: append buffers into mt_pending; the chunks are folded into
* mv_hex once, on the next read (materialize), instead of copying the whole
* buffer on every append (was O(n^2)).
    TYPES ty_chunks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    DATA mv_hex TYPE xstring.
    DATA mv_pos TYPE i.
    DATA mt_pending TYPE ty_chunks.

    METHODS materialize.
    CLASS-METHODS join_chunks
      IMPORTING
        it_chunks     TYPE ty_chunks
      RETURNING
        VALUE(rv_data) TYPE xstring.
ENDCLASS.



CLASS ZCL_OASSH_STREAM IMPLEMENTATION.


  METHOD append.
    DATA lv_chunk TYPE xstring.
    lv_chunk = iv_hex.
    APPEND lv_chunk TO mt_pending.
  ENDMETHOD.


  METHOD materialize.
* Drop the consumed prefix, then join pending bytes as a balanced tree. This
* prevents a long series of appends from repeatedly copying the complete
* accumulated stream.
    DATA lt_chunks TYPE ty_chunks.
    IF mt_pending IS INITIAL.
      RETURN.
    ENDIF.
    IF mv_pos > 0.
      mv_hex = mv_hex+mv_pos.
      mv_pos = 0.
    ENDIF.
    IF mv_hex IS NOT INITIAL.
      APPEND mv_hex TO lt_chunks.
    ENDIF.
    APPEND LINES OF mt_pending TO lt_chunks.
    mv_hex = join_chunks( lt_chunks ).
    CLEAR mt_pending.
  ENDMETHOD.


  METHOD join_chunks.
* Two-operand byte concatenation is portable on SAP and open-abap; the table
* form is not (see ANORMALIES.md). Pairwise joining also bounds copying.
    DATA lt_current TYPE ty_chunks.
    DATA lt_next TYPE ty_chunks.
    DATA lv_index TYPE i.
    DATA lv_count TYPE i.
    DATA lv_joined TYPE xstring.
    lt_current = it_chunks.
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
      rv_data = lt_current[ 1 ].
    ENDIF.
  ENDMETHOD.


  METHOD boolean_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5
* the value 0 represents FALSE, all non-zero values represent TRUE
    rv_boolean = boolc( take( 1 ) <> '00' ).
  ENDMETHOD.


  METHOD byte_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5
    rv_byte = take( 1 ).
  ENDMETHOD.


  METHOD byte_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5
    append( iv_byte ).
  ENDMETHOD.


  METHOD mpint_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5
* the magnitude is returned; the sign padding byte (if any) is stripped

    rv_int = string_decode( ).
    IF xstrlen( rv_int ) > 0 AND rv_int(1) = '00'.
      rv_int = rv_int+1.
    ENDIF.

  ENDMETHOD.


  METHOD mpint_decode_positive.
* Decode the non-negative, canonical subset of RFC 4251 mpint used by
* fixed-group Diffie-Hellman. Negative and redundant encodings are malformed.
    DATA lv_first TYPE x LENGTH 1.
    DATA lv_second TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.
    rv_int = string_decode( ).
    IF xstrlen( rv_int ) = 0.
      RETURN.
    ENDIF.
    lv_first = rv_int(1).
    GET BIT 1 OF lv_first INTO lv_bit.
    IF lv_first = '00'.
      IF xstrlen( rv_int ) = 1.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_second = rv_int+1(1).
      GET BIT 1 OF lv_second INTO lv_bit.
      IF lv_bit <> '1'.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      rv_int = rv_int+1.
    ELSEIF lv_bit = '1'.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD mpint_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5
* only non-negative integers are supported

    DATA lv_data TYPE xstring.
    DATA lv_first TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.

    lv_data = iv_int.

* unnecessary leading zero bytes MUST NOT be included
    WHILE xstrlen( lv_data ) > 0 AND lv_data(1) = '00'.
      lv_data = lv_data+1.
    ENDWHILE.

* if the most significant bit would be set for a positive number,
* the number MUST be preceded by a zero byte
    IF xstrlen( lv_data ) > 0.
      lv_first = lv_data(1).
      GET BIT 1 OF lv_first INTO lv_bit.
      IF lv_bit = '1'.
        DATA(lv_zero) = CONV xstring( '00' ).
        lv_data = lv_zero && lv_data.
      ENDIF.
    ENDIF.

    string_encode( lv_data ).

  ENDMETHOD.


  METHOD boolean_encode.
    CASE iv_boolean.
      WHEN abap_true.
        append( '01' ).
      WHEN abap_false.
        append( '00' ).
      WHEN OTHERS.
        ASSERT 1 = 2.
    ENDCASE.
  ENDMETHOD.


  METHOD clear.
    CLEAR mv_hex.
    CLEAR mv_pos.
    CLEAR mt_pending.
  ENDMETHOD.


  METHOD constructor.
    mv_hex = iv_hex.
  ENDMETHOD.


  METHOD get.
    materialize( ).
    rv_hex = mv_hex+mv_pos.
  ENDMETHOD.


  METHOD get_length.
    materialize( ).
    rv_length = xstrlen( mv_hex ) - mv_pos.
  ENDMETHOD.


  METHOD name_list_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    DATA lv_length TYPE i.
    DATA lv_hex TYPE xstring.
    DATA lv_text TYPE string.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_code TYPE i.
    DATA lv_name_length TYPE i.

    lv_length = uint32_decode( ).
    lv_hex = take( lv_length ).
    IF lv_length = 0.
      RETURN.
    ENDIF.
* RFC 4251 sections 4.2 and 5: each name is 1..64 printable, non-whitespace
* US-ASCII characters and list elements are separated by single commas.
* Validate bytes before from_xstring can filter malformed control characters.
    DO lv_length TIMES.
      lv_offset = sy-index - 1.
      lv_byte = lv_hex+lv_offset(1).
      lv_code = lv_byte.
      IF lv_byte = '2C'.
        IF lv_name_length = 0.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        CLEAR lv_name_length.
      ELSE.
        IF lv_code < 33 OR lv_code > 126.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_name_length = lv_name_length + 1.
        IF lv_name_length > 64.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
      ENDIF.
    ENDDO.
    IF lv_name_length = 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_text = zcl_oassh_ascii=>from_xstring( lv_hex ).
    SPLIT lv_text AT ',' INTO TABLE rt_list.

  ENDMETHOD.


  METHOD name_list_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    DATA lv_text TYPE string.
    CONCATENATE LINES OF it_list INTO lv_text SEPARATED BY ','.

    uint32_encode( strlen( lv_text ) ).
    append( zcl_oassh_ascii=>to_xstring( lv_text ) ).

  ENDMETHOD.


  METHOD string_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    DATA lv_len TYPE i.

    lv_len = uint32_decode( ).
    rv_string = take( lv_len ).

  ENDMETHOD.


  METHOD string_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    uint32_encode( xstrlen( iv_string ) ).
    append( iv_string ).

  ENDMETHOD.


  METHOD take.
    DATA lv_available TYPE i.
    materialize( ).
    lv_available = xstrlen( mv_hex ) - mv_pos.
    IF iv_length < 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF iv_length > lv_available.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    rv_hex = mv_hex+mv_pos(iv_length).
    mv_pos = mv_pos + iv_length.
  ENDMETHOD.


  METHOD uint32_decode.

    rv_int = take( 4 ).

  ENDMETHOD.


  METHOD uint32_decode_peek.

    materialize( ).
    rv_int = take( 4 ).
    mv_pos = mv_pos - 4.

  ENDMETHOD.


  METHOD uint32_encode.

    DATA lv_hex TYPE x LENGTH 4.
    lv_hex = iv_int.
    append( lv_hex ).

  ENDMETHOD.
ENDCLASS.
