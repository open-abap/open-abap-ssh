CLASS zcl_oassh_hmac DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* HMAC-SHA-256, RFC 2104 / FIPS 198-1, on top of zcl_oassh_sha256.

    CONSTANTS c_block_size TYPE i VALUE 64.

    CLASS-METHODS sha256
      IMPORTING
        iv_key       TYPE xstring
        iv_data      TYPE xstring
      RETURNING
        VALUE(rv_mac) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CLASS-METHODS xor_block
      IMPORTING
        iv_block    TYPE xstring
        iv_pad      TYPE x
      RETURNING
        VALUE(rv_r) TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_hmac IMPLEMENTATION.


  METHOD xor_block.
* XOR every byte of a block-sized key with the pad byte
    DATA lv_offset TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.

    DO c_block_size TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_block+lv_offset(1).
      lv_byte = lv_byte BIT-XOR iv_pad.
      CONCATENATE rv_r lv_byte INTO rv_r IN BYTE MODE.
    ENDDO.

  ENDMETHOD.


  METHOD sha256.
* HMAC(K, m) = H( (K0 XOR opad) || H( (K0 XOR ipad) || m ) )
    DATA lv_k0          TYPE xstring.
    DATA lv_zero        TYPE x LENGTH 1 VALUE '00'.
    DATA lv_ipad_key    TYPE xstring.
    DATA lv_opad_key    TYPE xstring.
    DATA lv_inner_input TYPE xstring.
    DATA lv_inner       TYPE xstring.
    DATA lv_outer_input TYPE xstring.

* keys longer than the block are hashed first, then all keys are
* right-padded with zeros to the block size
    IF xstrlen( iv_key ) > c_block_size.
      lv_k0 = zcl_oassh_sha256=>hash( iv_key ).
    ELSE.
      lv_k0 = iv_key.
    ENDIF.
    WHILE xstrlen( lv_k0 ) < c_block_size.
      CONCATENATE lv_k0 lv_zero INTO lv_k0 IN BYTE MODE.
    ENDWHILE.

    lv_ipad_key = xor_block(
      iv_block = lv_k0
      iv_pad   = '36' ).
    lv_opad_key = xor_block(
      iv_block = lv_k0
      iv_pad   = '5C' ).

    CONCATENATE lv_ipad_key iv_data INTO lv_inner_input IN BYTE MODE.
    lv_inner = zcl_oassh_sha256=>hash( lv_inner_input ).

    CONCATENATE lv_opad_key lv_inner INTO lv_outer_input IN BYTE MODE.
    rv_mac = zcl_oassh_sha256=>hash( lv_outer_input ).

  ENDMETHOD.
ENDCLASS.
