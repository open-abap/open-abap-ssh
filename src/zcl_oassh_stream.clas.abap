class ZCL_OASSH_STREAM definition
  public
  final
  create public .

public section.

  methods CONSTRUCTOR
    importing
      !IV_HEX type XSTRING optional .
  methods GET
    returning
      value(RV_HEX) type XSTRING .
  methods TAKE
    importing
      !IV_LENGTH type I
    returning
      value(RV_HEX) type XSTRING .
  methods APPEND
    importing
      !IV_HEX type XSEQUENCE .
  methods NAME_LIST_ENCODE
    importing
      !IT_LIST type STRING_TABLE .
  methods BOOLEAN_ENCODE
    importing
      !IV_BOOLEAN type ABAP_BOOL .
  methods BOOLEAN_DECODE
    returning
      value(RV_BOOLEAN) type ABAP_BOOL .
  methods NAME_LIST_DECODE
    returning
      value(RT_LIST) type STRING_TABLE .
  methods UINT32_ENCODE
    importing
      !IV_INT type I .
  methods UINT32_DECODE
    returning
      value(RV_INT) type I .
  methods UINT32_DECODE_PEEK
    returning
      value(RV_INT) type I .
  methods GET_LENGTH
    returning
      value(RV_LENGTH) type I .
  methods CLEAR .
  PROTECTED SECTION.
private section.

  data MV_HEX type XSTRING .
ENDCLASS.



CLASS ZCL_OASSH_STREAM IMPLEMENTATION.


  METHOD append.
    mv_hex = mv_hex && iv_hex.
  ENDMETHOD.


  METHOD boolean_decode.
    rv_boolean = boolc( take( 1 ) = '00' ).
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
