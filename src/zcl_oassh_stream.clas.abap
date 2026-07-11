CLASS zcl_oassh_stream DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.

    METHODS constructor
      IMPORTING
        !iv_hex TYPE xstring OPTIONAL .
    METHODS get
      RETURNING
        VALUE(rv_hex) TYPE xstring .
    METHODS take
      IMPORTING
        !iv_length    TYPE i
      RETURNING
        VALUE(rv_hex) TYPE xstring .
    METHODS append
      IMPORTING
        !iv_hex TYPE xsequence .
    METHODS name_list_encode
      IMPORTING
        !it_list TYPE string_table .
    METHODS boolean_encode
      IMPORTING
        !iv_boolean TYPE abap_bool .
    METHODS boolean_decode
      RETURNING
        VALUE(rv_boolean) TYPE abap_bool .
    METHODS byte_encode
      IMPORTING
        !iv_byte TYPE x .
    METHODS byte_decode
      RETURNING
        VALUE(rv_byte) TYPE x .
    METHODS mpint_encode
      IMPORTING
        !iv_int TYPE xsequence .
    METHODS mpint_decode
      RETURNING
        VALUE(rv_int) TYPE xstring .
    METHODS name_list_decode
      RETURNING
        VALUE(rt_list) TYPE string_table .
    METHODS uint32_encode
      IMPORTING
        !iv_int TYPE i .
    METHODS uint32_decode
      RETURNING
        VALUE(rv_int) TYPE i .
    METHODS uint32_decode_peek
      RETURNING
        VALUE(rv_int) TYPE i .
    METHODS get_length
      RETURNING
        VALUE(rv_length) TYPE i .
    METHODS clear .
    METHODS string_encode
      IMPORTING
        !iv_string TYPE xstring .
    METHODS string_decode
      RETURNING
        VALUE(rv_string) TYPE xstring .
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mv_hex TYPE xstring .
ENDCLASS.



CLASS ZCL_OASSH_STREAM IMPLEMENTATION.


  METHOD append.
    mv_hex = mv_hex && iv_hex.
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
  ENDMETHOD.


  METHOD constructor.
    mv_hex = iv_hex.
  ENDMETHOD.


  METHOD get.
    rv_hex = mv_hex.
  ENDMETHOD.


  METHOD get_length.
    rv_length = xstrlen( mv_hex ).
  ENDMETHOD.


  METHOD name_list_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    DATA lv_length TYPE i.
    DATA lv_hex TYPE xstring.
    DATA lv_text TYPE string.

    lv_length = uint32_decode( ).
    lv_hex = mv_hex(lv_length).
    lv_text = cl_abap_codepage=>convert_from( lv_hex ).
    SPLIT lv_text AT ',' INTO TABLE rt_list.
    take( lv_length ).

  ENDMETHOD.


  METHOD name_list_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

    DATA lv_text TYPE string.
    CONCATENATE LINES OF it_list INTO lv_text SEPARATED BY ','.

    uint32_encode( strlen( lv_text ) ).
    append( cl_abap_codepage=>convert_to( lv_text ) ).

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
    rv_hex = mv_hex(iv_length).
    mv_hex = mv_hex+iv_length.
  ENDMETHOD.


  METHOD uint32_decode.

    rv_int = take( 4 ).

  ENDMETHOD.


  METHOD uint32_decode_peek.

    rv_int = mv_hex(4).

  ENDMETHOD.


  METHOD uint32_encode.

    DATA lv_hex TYPE x LENGTH 4.
    lv_hex = iv_int.
    append( lv_hex ).

  ENDMETHOD.
ENDCLASS.
