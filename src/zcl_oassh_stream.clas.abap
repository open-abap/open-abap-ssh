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
    METHODS name_list_decode
      RETURNING
        VALUE(rt_list) TYPE string_table .
    METHODS uint32_encode
      IMPORTING
        !iv_int TYPE i .
    METHODS uint32_decode
      RETURNING
        VALUE(rv_int) TYPE i .
    METHODS get_length
      RETURNING
        VALUE(rv_length) TYPE i .
  PROTECTED SECTION.
  PRIVATE SECTION.
    DATA mv_hex TYPE xstring.
ENDCLASS.



CLASS ZCL_OASSH_STREAM IMPLEMENTATION.


  METHOD append.
    mv_hex = mv_hex && iv_hex.
  ENDMETHOD.


  METHOD boolean_decode.
    rv_boolean = boolc( take( 1 ) = '00' ) .
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


  METHOD take.
    rv_hex = mv_hex(iv_length).
    mv_hex = mv_hex+iv_length.
  ENDMETHOD.


  METHOD uint32_decode.

    rv_int = take( 4 ).

  ENDMETHOD.


  METHOD uint32_encode.

    DATA lv_hex TYPE x LENGTH 4.
    lv_hex = iv_int.
    append( lv_hex ).

  ENDMETHOD.
ENDCLASS.
