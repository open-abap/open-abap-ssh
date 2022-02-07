CLASS zcl_oassh_stream DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
    METHODS constructor
      IMPORTING iv_hex TYPE xstring OPTIONAL.

    METHODS get
      RETURNING VALUE(rv_hex) TYPE xstring.

    METHODS name_list_encode
      IMPORTING
        !it_list TYPE string_table.

    METHODS name_list_decode
      RETURNING
        VALUE(rt_list) TYPE string_table.

    METHODS uint32_encode
      IMPORTING iv_int TYPE i.

    METHODS uint32_decode
      RETURNING VALUE(rv_int) TYPE i.

  PROTECTED SECTION.
  PRIVATE SECTION.
    DATA mv_hex TYPE xstring.
ENDCLASS.



CLASS ZCL_OASSH_STREAM IMPLEMENTATION.


  METHOD constructor.
    mv_hex = iv_hex.
  ENDMETHOD.


  METHOD get.
    rv_hex = mv_hex.
  ENDMETHOD.


  METHOD name_list_decode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

  ENDMETHOD.


  METHOD name_list_encode.
* https://datatracker.ietf.org/doc/html/rfc4251#section-5

  ENDMETHOD.


  METHOD uint32_decode.

  ENDMETHOD.


  METHOD uint32_encode.

  ENDMETHOD.
ENDCLASS.
