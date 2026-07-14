CLASS zcl_oassh_x25519 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* X25519 (RFC 7748) scalar multiplication on Curve25519. Scalars and
* u-coordinates are 32-byte little-endian strings, as used on the wire.
* Field arithmetic runs on zcl_oassh_field25519's base-2^26 integer limbs,
* not the byte-string bignum, so the ladder avoids per-byte xstring work.

    CLASS-METHODS scalarmult
      IMPORTING
        iv_scalar        TYPE xstring
        iv_u             TYPE xstring
      RETURNING
        VALUE(rv_result) TYPE xstring.
    CLASS-METHODS scalarmult_base
      IMPORTING
        iv_scalar        TYPE xstring
      RETURNING
        VALUE(rv_result) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.
    TYPES ty_field TYPE zcl_oassh_field25519=>ty_field.
ENDCLASS.



CLASS zcl_oassh_x25519 IMPLEMENTATION.


  METHOD scalarmult_base.
    DATA lv_u TYPE xstring.

    lv_u = '0900000000000000000000000000000000000000000000000000000000000000'.
    rv_result = scalarmult(
      iv_scalar = iv_scalar
      iv_u      = lv_u ).
  ENDMETHOD.


  METHOD scalarmult.
* RFC 7748 5. Montgomery ladder on x-coordinates
    DATA lv_k       TYPE xstring.
    DATA lv_u       TYPE xstring.
    DATA lv_byte    TYPE x LENGTH 1.
    DATA lv_x1      TYPE ty_field.
    DATA lv_x2      TYPE ty_field.
    DATA lv_z2      TYPE ty_field.
    DATA lv_x3      TYPE ty_field.
    DATA lv_z3      TYPE ty_field.
    DATA lv_swap    TYPE i.
    DATA lv_kt      TYPE i.
    DATA lv_t       TYPE i.
    DATA lv_byteidx TYPE i.
    DATA lv_bitpos  TYPE i.
    DATA lv_bit     TYPE c LENGTH 1.
    DATA lv_tmp     TYPE ty_field.
    DATA lv_a       TYPE ty_field.
    DATA lv_aa      TYPE ty_field.
    DATA lv_b       TYPE ty_field.
    DATA lv_bb      TYPE ty_field.
    DATA lv_e       TYPE ty_field.
    DATA lv_c       TYPE ty_field.
    DATA lv_d       TYPE ty_field.
    DATA lv_da      TYPE ty_field.
    DATA lv_cb      TYPE ty_field.
    DATA lv_sum     TYPE ty_field.
    DATA lv_diff    TYPE ty_field.
    DATA lv_a24     TYPE ty_field.
    DATA lv_prefix  TYPE xstring.
    DATA lv_f8      TYPE x LENGTH 1 VALUE 'F8'.
    DATA lv_7f      TYPE x LENGTH 1 VALUE '7F'.
    DATA lv_40      TYPE x LENGTH 1 VALUE '40'.

* a24 = (486662 - 2) / 4 = 121665
    lv_a24 = zcl_oassh_field25519=>from_be( '01DB41' ).

* clamp the scalar (RFC 7748 decodeScalar25519); xstrings cannot be
* written by offset, so rebuild the string around the edited bytes
    lv_byte = iv_scalar+0(1).
    lv_byte = lv_byte BIT-AND lv_f8.
    lv_prefix = iv_scalar+1.
    CONCATENATE lv_byte lv_prefix INTO lv_k IN BYTE MODE.

    lv_byte = lv_k+31(1).
    lv_byte = lv_byte BIT-AND lv_7f.
    lv_byte = lv_byte BIT-OR lv_40.
    lv_prefix = lv_k(31).
    CONCATENATE lv_prefix lv_byte INTO lv_k IN BYTE MODE.

* mask the u-coordinate's top bit, then decode it little-endian
    lv_byte = iv_u+31(1).
    lv_byte = lv_byte BIT-AND lv_7f.
    lv_prefix = iv_u(31).
    CONCATENATE lv_prefix lv_byte INTO lv_u IN BYTE MODE.
    lv_x1 = zcl_oassh_field25519=>from_le( lv_u ).

    lv_x2 = zcl_oassh_field25519=>one( ).
    lv_z2 = zcl_oassh_field25519=>zero( ).
    lv_x3 = lv_x1.
    lv_z3 = zcl_oassh_field25519=>one( ).
    lv_swap = 0.

    DO 255 TIMES.
      lv_t = 255 - sy-index.

      lv_byteidx = lv_t DIV 8.
      lv_bitpos = 8 - lv_t MOD 8.
      lv_byte = lv_k+lv_byteidx(1).
      GET BIT lv_bitpos OF lv_byte INTO lv_bit.
      lv_kt = 0.
      IF lv_bit = '1'.
        lv_kt = 1.
      ENDIF.

      lv_swap = ( lv_swap + lv_kt ) MOD 2.
      IF lv_swap = 1.
        lv_tmp = lv_x2.
        lv_x2 = lv_x3.
        lv_x3 = lv_tmp.
        lv_tmp = lv_z2.
        lv_z2 = lv_z3.
        lv_z3 = lv_tmp.
      ENDIF.
      lv_swap = lv_kt.

      lv_a = zcl_oassh_field25519=>add(
        it_a = lv_x2
        it_b = lv_z2 ).
      lv_aa = zcl_oassh_field25519=>sqr( lv_a ).
      lv_b = zcl_oassh_field25519=>sub(
        it_a = lv_x2
        it_b = lv_z2 ).
      lv_bb = zcl_oassh_field25519=>sqr( lv_b ).
      lv_e = zcl_oassh_field25519=>sub(
        it_a = lv_aa
        it_b = lv_bb ).
      lv_c = zcl_oassh_field25519=>add(
        it_a = lv_x3
        it_b = lv_z3 ).
      lv_d = zcl_oassh_field25519=>sub(
        it_a = lv_x3
        it_b = lv_z3 ).
      lv_da = zcl_oassh_field25519=>mul(
        it_a = lv_d
        it_b = lv_a ).
      lv_cb = zcl_oassh_field25519=>mul(
        it_a = lv_c
        it_b = lv_b ).

      lv_sum = zcl_oassh_field25519=>add(
        it_a = lv_da
        it_b = lv_cb ).
      lv_x3 = zcl_oassh_field25519=>sqr( lv_sum ).

      lv_diff = zcl_oassh_field25519=>sub(
        it_a = lv_da
        it_b = lv_cb ).
      lv_diff = zcl_oassh_field25519=>sqr( lv_diff ).
      lv_z3 = zcl_oassh_field25519=>mul(
        it_a = lv_x1
        it_b = lv_diff ).

      lv_x2 = zcl_oassh_field25519=>mul(
        it_a = lv_aa
        it_b = lv_bb ).

      lv_tmp = zcl_oassh_field25519=>mul(
        it_a = lv_a24
        it_b = lv_e ).
      lv_tmp = zcl_oassh_field25519=>add(
        it_a = lv_aa
        it_b = lv_tmp ).
      lv_z2 = zcl_oassh_field25519=>mul(
        it_a = lv_e
        it_b = lv_tmp ).
    ENDDO.

    IF lv_swap = 1.
      lv_tmp = lv_x2.
      lv_x2 = lv_x3.
      lv_x3 = lv_tmp.
      lv_tmp = lv_z2.
      lv_z2 = lv_z3.
      lv_z3 = lv_tmp.
    ENDIF.

    lv_tmp = zcl_oassh_field25519=>mul(
      it_a = lv_x2
      it_b = zcl_oassh_field25519=>inv( lv_z2 ) ).

    rv_result = zcl_oassh_field25519=>to_le( lv_tmp ).
  ENDMETHOD.
ENDCLASS.
