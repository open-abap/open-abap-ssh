CLASS zcl_oassh_x25519 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* X25519 (RFC 7748) scalar multiplication on Curve25519. Scalars and
* u-coordinates are 32-byte little-endian strings, as used on the wire.
* Field arithmetic is mod p = 2^255 - 19 with fast folding reduction.

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

    CLASS-METHODS prime
      RETURNING
        VALUE(rv_p) TYPE xstring.
    CLASS-METHODS f_reduce
      IMPORTING
        iv_x        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS f_add
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS f_sub
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS f_mul
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS f_inv
      IMPORTING
        iv_a        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS reverse_bytes
      IMPORTING
        iv_x        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS pad32
      IMPORTING
        iv_x        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS encode_le
      IMPORTING
        iv_be       TYPE xstring
      RETURNING
        VALUE(rv_le) TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_x25519 IMPLEMENTATION.


  METHOD prime.
    rv_p = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED'.
  ENDMETHOD.


  METHOD f_reduce.
* reduce mod 2^255 - 19: fold the part above 2^256 back in as x38, since
* 2^256 = 2 * 2^255 == 38 (mod p), then a final few subtractions
    DATA lv_len    TYPE i.
    DATA lv_hi_len TYPE i.
    DATA lv_hi     TYPE xstring.
    DATA lv_lo     TYPE xstring.
    DATA lv_folded TYPE xstring.
    DATA lv_p      TYPE xstring.

    rv_r = iv_x.

    lv_len = xstrlen( rv_r ).
    WHILE lv_len > 32.
      lv_hi_len = lv_len - 32.
      lv_hi = rv_r(lv_hi_len).
      lv_lo = rv_r+lv_hi_len(32).
      lv_folded = zcl_oassh_bigint=>multiply(
        iv_a = lv_hi
        iv_b = '26' ).
      rv_r = zcl_oassh_bigint=>add(
        iv_a = lv_lo
        iv_b = lv_folded ).
      lv_len = xstrlen( rv_r ).
    ENDWHILE.

    lv_p = prime( ).
    WHILE zcl_oassh_bigint=>compare(
        iv_a = rv_r
        iv_b = lv_p ) >= 0.
      rv_r = zcl_oassh_bigint=>subtract(
        iv_a = rv_r
        iv_b = lv_p ).
    ENDWHILE.
  ENDMETHOD.


  METHOD f_add.
    rv_r = f_reduce( zcl_oassh_bigint=>add(
      iv_a = iv_a
      iv_b = iv_b ) ).
  ENDMETHOD.


  METHOD f_sub.
* a - b mod p; if a < b add p first so the result stays non-negative
    DATA lv_a TYPE xstring.

    IF zcl_oassh_bigint=>compare(
        iv_a = iv_a
        iv_b = iv_b ) >= 0.
      rv_r = zcl_oassh_bigint=>subtract(
        iv_a = iv_a
        iv_b = iv_b ).
    ELSE.
      lv_a = zcl_oassh_bigint=>add(
        iv_a = iv_a
        iv_b = prime( ) ).
      rv_r = zcl_oassh_bigint=>subtract(
        iv_a = lv_a
        iv_b = iv_b ).
    ENDIF.
  ENDMETHOD.


  METHOD f_mul.
    rv_r = f_reduce( zcl_oassh_bigint=>multiply(
      iv_a = iv_a
      iv_b = iv_b ) ).
  ENDMETHOD.


  METHOD f_inv.
* a^(p-2) mod p by square-and-multiply using the fast field multiply
    DATA lv_exp       TYPE xstring.
    DATA lv_base      TYPE xstring.
    DATA lv_nbits     TYPE i.
    DATA lv_bitidx    TYPE i.
    DATA lv_byteoff   TYPE i.
    DATA lv_bitinbyte TYPE i.
    DATA lv_bytex     TYPE x LENGTH 1.
    DATA lv_bit       TYPE c LENGTH 1.

    lv_exp = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB'.
    lv_base = f_reduce( iv_a ).
    rv_r = '01'.

    lv_nbits = xstrlen( lv_exp ) * 8.
    DO lv_nbits TIMES.
      lv_bitidx = sy-index - 1.
      lv_byteoff = lv_bitidx DIV 8.
      lv_bitinbyte = lv_bitidx MOD 8 + 1.
      lv_bytex = lv_exp+lv_byteoff(1).
      GET BIT lv_bitinbyte OF lv_bytex INTO lv_bit.

      rv_r = f_mul(
        iv_a = rv_r
        iv_b = rv_r ).
      IF lv_bit = '1'.
        rv_r = f_mul(
          iv_a = rv_r
          iv_b = lv_base ).
      ENDIF.
    ENDDO.
  ENDMETHOD.


  METHOD reverse_bytes.
    DATA lv_len  TYPE i.
    DATA lv_off  TYPE i.
    DATA lv_byte TYPE x LENGTH 1.

    lv_len = xstrlen( iv_x ).
    DO lv_len TIMES.
      lv_off = lv_len - sy-index.
      lv_byte = iv_x+lv_off(1).
      CONCATENATE rv_r lv_byte INTO rv_r IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD pad32.
    DATA lv_zero TYPE x LENGTH 1 VALUE '00'.

    rv_r = iv_x.
    WHILE xstrlen( rv_r ) < 32.
      CONCATENATE lv_zero rv_r INTO rv_r IN BYTE MODE.
    ENDWHILE.
  ENDMETHOD.


  METHOD encode_le.
    rv_le = reverse_bytes( pad32( iv_be ) ).
  ENDMETHOD.


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
    DATA lv_x1      TYPE xstring.
    DATA lv_x2      TYPE xstring.
    DATA lv_z2      TYPE xstring.
    DATA lv_x3      TYPE xstring.
    DATA lv_z3      TYPE xstring.
    DATA lv_swap    TYPE i.
    DATA lv_kt      TYPE i.
    DATA lv_t       TYPE i.
    DATA lv_byteidx TYPE i.
    DATA lv_bitpos  TYPE i.
    DATA lv_bit     TYPE c LENGTH 1.
    DATA lv_tmp     TYPE xstring.
    DATA lv_a       TYPE xstring.
    DATA lv_aa      TYPE xstring.
    DATA lv_b       TYPE xstring.
    DATA lv_bb      TYPE xstring.
    DATA lv_e       TYPE xstring.
    DATA lv_c       TYPE xstring.
    DATA lv_d       TYPE xstring.
    DATA lv_da      TYPE xstring.
    DATA lv_cb      TYPE xstring.
    DATA lv_sum     TYPE xstring.
    DATA lv_diff    TYPE xstring.
    DATA lv_a24     TYPE xstring.
    DATA lv_prefix  TYPE xstring.
    DATA lv_f8      TYPE x LENGTH 1 VALUE 'F8'.
    DATA lv_7f      TYPE x LENGTH 1 VALUE '7F'.
    DATA lv_40      TYPE x LENGTH 1 VALUE '40'.

    lv_a24 = '01DB41'.

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

* mask the u-coordinate's top bit, then use it big-endian
    lv_byte = iv_u+31(1).
    lv_byte = lv_byte BIT-AND lv_7f.
    lv_prefix = iv_u(31).
    CONCATENATE lv_prefix lv_byte INTO lv_u IN BYTE MODE.
    lv_x1 = reverse_bytes( lv_u ).

    lv_x2 = '01'.
    lv_z3 = '01'.
    lv_x3 = lv_x1.
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

      lv_a = f_add(
        iv_a = lv_x2
        iv_b = lv_z2 ).
      lv_aa = f_mul(
        iv_a = lv_a
        iv_b = lv_a ).
      lv_b = f_sub(
        iv_a = lv_x2
        iv_b = lv_z2 ).
      lv_bb = f_mul(
        iv_a = lv_b
        iv_b = lv_b ).
      lv_e = f_sub(
        iv_a = lv_aa
        iv_b = lv_bb ).
      lv_c = f_add(
        iv_a = lv_x3
        iv_b = lv_z3 ).
      lv_d = f_sub(
        iv_a = lv_x3
        iv_b = lv_z3 ).
      lv_da = f_mul(
        iv_a = lv_d
        iv_b = lv_a ).
      lv_cb = f_mul(
        iv_a = lv_c
        iv_b = lv_b ).

      lv_sum = f_add(
        iv_a = lv_da
        iv_b = lv_cb ).
      lv_x3 = f_mul(
        iv_a = lv_sum
        iv_b = lv_sum ).

      lv_diff = f_sub(
        iv_a = lv_da
        iv_b = lv_cb ).
      lv_diff = f_mul(
        iv_a = lv_diff
        iv_b = lv_diff ).
      lv_z3 = f_mul(
        iv_a = lv_x1
        iv_b = lv_diff ).

      lv_x2 = f_mul(
        iv_a = lv_aa
        iv_b = lv_bb ).

      lv_tmp = f_mul(
        iv_a = lv_a24
        iv_b = lv_e ).
      lv_tmp = f_add(
        iv_a = lv_aa
        iv_b = lv_tmp ).
      lv_z2 = f_mul(
        iv_a = lv_e
        iv_b = lv_tmp ).
    ENDDO.

    IF lv_swap = 1.
      lv_tmp = lv_x2.
      lv_x2 = lv_x3.
      lv_x3 = lv_tmp.
      lv_tmp = lv_z2.
      lv_z2 = lv_z3.
      lv_z3 = lv_tmp.
    ENDIF.

    lv_tmp = f_mul(
      iv_a = lv_x2
      iv_b = f_inv( lv_z2 ) ).

    rv_result = encode_le( lv_tmp ).
  ENDMETHOD.
ENDCLASS.
