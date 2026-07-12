CLASS zcl_oassh_field25519 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* Arithmetic in GF(2^255 - 19), the shared prime field of Curve25519 and
* Ed25519. Elements are 26 little-endian limbs of base 2^10, chosen so a
* schoolbook multiply and its folding reduction stay inside ABAP's signed
* 32-bit integer range. This is the field layer for zcl_oassh_x25519; the
* implementation is the one proven by the Ed25519 RFC 8032 vectors and can
* also back zcl_oassh_ed25519.

    TYPES ty_field TYPE STANDARD TABLE OF i WITH EMPTY KEY.

    CLASS-METHODS from_le
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS from_be
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS to_le
      IMPORTING it_field TYPE ty_field
      RETURNING VALUE(rv_data) TYPE xstring.
    CLASS-METHODS add
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS sub
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS mul
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS inv
      IMPORTING it_a TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS one
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS zero
      RETURNING VALUE(rt_field) TYPE ty_field.

  PRIVATE SECTION.
    CONSTANTS c_base TYPE i VALUE 1024.
    CONSTANTS c_limbs TYPE i VALUE 26.
* p - 2, the Fermat inverse exponent, big-endian
    CONSTANTS c_inv_exp TYPE xstring VALUE
      '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB'.

    CLASS-METHODS reverse_bytes
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rv_data) TYPE xstring.
    CLASS-METHODS modulus
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS normalize
      IMPORTING it_field TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS compare
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rv_compare) TYPE i.
    CLASS-METHODS sub_raw
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS pow
      IMPORTING
        it_base TYPE ty_field
        iv_exp TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
ENDCLASS.


CLASS zcl_oassh_field25519 IMPLEMENTATION.

  METHOD reverse_bytes.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DO xstrlen( iv_data ) TIMES.
      lv_offset = xstrlen( iv_data ) - sy-index.
      lv_byte = iv_data+lv_offset(1).
      CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD from_le.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_acc TYPE i.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE i VALUE 1.
    DO xstrlen( iv_data ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_data+lv_offset(1).
      lv_acc = lv_acc + lv_byte * lv_factor.
      lv_bits = lv_bits + 8.
      WHILE lv_bits >= 10.
        APPEND lv_acc MOD c_base TO rt_field.
        lv_acc = lv_acc DIV c_base.
        lv_bits = lv_bits - 10.
        lv_factor = 1.
        DO lv_bits TIMES.
          lv_factor = lv_factor * 2.
        ENDDO.
      ENDWHILE.
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
    ENDDO.
    IF lv_bits > 0.
      APPEND lv_acc TO rt_field.
    ENDIF.
    WHILE lines( rt_field ) < c_limbs.
      APPEND 0 TO rt_field.
    ENDWHILE.
  ENDMETHOD.


  METHOD from_be.
    rt_field = from_le( reverse_bytes( iv_data ) ).
  ENDMETHOD.


  METHOD to_le.
    DATA lv_acc TYPE i.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE i.
    DATA lv_limb TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_zero TYPE x LENGTH 1 VALUE '00'.
    LOOP AT it_field INTO lv_limb.
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
      lv_acc = lv_acc + lv_limb * lv_factor.
      lv_bits = lv_bits + 10.
      WHILE lv_bits >= 8.
        lv_byte = lv_acc MOD 256.
        CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
        lv_acc = lv_acc DIV 256.
        lv_bits = lv_bits - 8.
      ENDWHILE.
    ENDLOOP.
    IF lv_acc > 0.
      lv_byte = lv_acc.
      CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
    ENDIF.
    WHILE xstrlen( rv_data ) < 32.
      CONCATENATE rv_data lv_zero INTO rv_data IN BYTE MODE.
    ENDWHILE.
  ENDMETHOD.


  METHOD modulus.
    APPEND 1005 TO rt_field.
    DO 24 TIMES.
      APPEND 1023 TO rt_field.
    ENDDO.
    APPEND 31 TO rt_field.
  ENDMETHOD.


  METHOD compare.
    DATA lv_index TYPE i VALUE c_limbs.
    WHILE lv_index > 0.
      IF it_a[ lv_index ] > it_b[ lv_index ].
        rv_compare = 1.
        RETURN.
      ELSEIF it_a[ lv_index ] < it_b[ lv_index ].
        rv_compare = -1.
        RETURN.
      ENDIF.
      lv_index = lv_index - 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD sub_raw.
    DATA lv_index TYPE i.
    DATA lv_value TYPE i.
    DATA lv_borrow TYPE i.
    rt_field = it_a.
    DO c_limbs TIMES.
      lv_index = sy-index.
      lv_value = rt_field[ lv_index ] - it_b[ lv_index ] - lv_borrow.
      IF lv_value < 0.
        lv_value = lv_value + c_base.
        lv_borrow = 1.
      ELSE.
        CLEAR lv_borrow.
      ENDIF.
      rt_field[ lv_index ] = lv_value.
    ENDDO.
    ASSERT lv_borrow = 0.
  ENDMETHOD.


  METHOD normalize.
    DATA lv_index TYPE i.
    DATA lv_low_index TYPE i.
    DATA lv_value TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_high TYPE i.
    DATA lt_p TYPE ty_field.
    rt_field = it_field.
    IF rt_field IS INITIAL.
      DO c_limbs TIMES.
        APPEND 0 TO rt_field.
      ENDDO.
      RETURN.
    ENDIF.
* Normalize the convolution before folding 2^260 = 608 modulo p.
    DO lines( rt_field ) TIMES.
      lv_index = sy-index.
      lv_value = rt_field[ lv_index ] + lv_carry.
      rt_field[ lv_index ] = lv_value MOD c_base.
      lv_carry = lv_value DIV c_base.
    ENDDO.
    WHILE lv_carry > 0.
      APPEND lv_carry MOD c_base TO rt_field.
      lv_carry = lv_carry DIV c_base.
    ENDWHILE.
    lv_index = lines( rt_field ).
    WHILE lv_index > c_limbs.
      lv_value = rt_field[ lv_index ].
      DELETE rt_field INDEX lv_index.
      lv_low_index = lv_index - c_limbs.
      rt_field[ lv_low_index ] = rt_field[ lv_low_index ] + 608 * lv_value.
      lv_index = lv_index - 1.
    ENDWHILE.
    WHILE lines( rt_field ) < c_limbs.
      APPEND 0 TO rt_field.
    ENDWHILE.
    DO.
      CLEAR lv_carry.
      DO c_limbs TIMES.
        lv_index = sy-index.
        lv_value = rt_field[ lv_index ] + lv_carry.
        rt_field[ lv_index ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      IF lv_carry > 0.
        rt_field[ 1 ] = rt_field[ 1 ] + 608 * lv_carry.
        CONTINUE.
      ENDIF.
      lv_high = rt_field[ c_limbs ] DIV 32.
      rt_field[ c_limbs ] = rt_field[ c_limbs ] MOD 32.
      IF lv_high > 0.
        rt_field[ 1 ] = rt_field[ 1 ] + 19 * lv_high.
        CONTINUE.
      ENDIF.
      EXIT.
    ENDDO.
    lt_p = modulus( ).
    IF compare( it_a = rt_field
                it_b = lt_p ) >= 0.
      rt_field = sub_raw( it_a = rt_field
                          it_b = lt_p ).
    ENDIF.
  ENDMETHOD.


  METHOD add.
    DATA lv_index TYPE i.
    DO c_limbs TIMES.
      lv_index = sy-index.
      APPEND it_a[ lv_index ] + it_b[ lv_index ] TO rt_field.
    ENDDO.
    rt_field = normalize( rt_field ).
  ENDMETHOD.


  METHOD sub.
    DATA lt_p TYPE ty_field.
    DATA lt_sum TYPE ty_field.
    DATA lv_index TYPE i.
    IF compare( it_a = it_a
                it_b = it_b ) >= 0.
      rt_field = sub_raw( it_a = it_a
                          it_b = it_b ).
    ELSE.
      lt_p = modulus( ).
      DO c_limbs TIMES.
        lv_index = sy-index.
        APPEND it_a[ lv_index ] + lt_p[ lv_index ] TO lt_sum.
      ENDDO.
      rt_field = sub_raw( it_a = lt_sum
                          it_b = it_b ).
    ENDIF.
    rt_field = normalize( rt_field ).
  ENDMETHOD.


  METHOD mul.
    DATA lv_i TYPE i.
    DATA lv_j TYPE i.
    DATA lv_position TYPE i.
    DO c_limbs * 2 - 1 TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
    DO c_limbs TIMES.
      lv_i = sy-index.
      DO c_limbs TIMES.
        lv_j = sy-index.
        lv_position = lv_i + lv_j - 1.
        rt_field[ lv_position ] = rt_field[ lv_position ]
          + it_a[ lv_i ] * it_b[ lv_j ].
      ENDDO.
    ENDDO.
    rt_field = normalize( rt_field ).
  ENDMETHOD.


  METHOD one.
    APPEND 1 TO rt_field.
    DO c_limbs - 1 TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
  ENDMETHOD.


  METHOD zero.
    DO c_limbs TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
  ENDMETHOD.


  METHOD pow.
    DATA lv_offset TYPE i.
    DATA lv_bit_index TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.
    rt_field = one( ).
    DO xstrlen( iv_exp ) * 8 TIMES.
      lv_offset = ( sy-index - 1 ) DIV 8.
      lv_bit_index = ( sy-index - 1 ) MOD 8 + 1.
      lv_byte = iv_exp+lv_offset(1).
      GET BIT lv_bit_index OF lv_byte INTO lv_bit.
      rt_field = mul( it_a = rt_field
                      it_b = rt_field ).
      IF lv_bit = '1'.
        rt_field = mul( it_a = rt_field
                        it_b = it_base ).
      ENDIF.
    ENDDO.
  ENDMETHOD.


  METHOD inv.
    rt_field = pow( it_base = it_a
                    iv_exp  = c_inv_exp ).
  ENDMETHOD.

ENDCLASS.
