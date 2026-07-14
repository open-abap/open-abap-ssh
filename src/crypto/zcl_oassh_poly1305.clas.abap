CLASS zcl_oassh_poly1305 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* RFC 8439 Poly1305. Thirteen-bit limbs keep the complete multiplication
* and reduction below ABAP's signed 32-bit integer ceiling: an unreduced
* accumulator limb stays below 2^14, so a convolution column peaks at
* 10 * 2^14 * 2^13 < 2^31.
    CLASS-METHODS auth
      IMPORTING
        iv_key                TYPE xstring
        iv_data               TYPE xstring
      RETURNING VALUE(rv_tag) TYPE xstring.
  PRIVATE SECTION.
    TYPES ty_limbs TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    CONSTANTS c_base TYPE i VALUE 8192.
    CONSTANTS c_limb_count TYPE i VALUE 10.
    CLASS-DATA gt_modulus TYPE ty_limbs.
    CLASS-METHODS from_little
      IMPORTING iv_data         TYPE xstring
      RETURNING VALUE(rt_limbs) TYPE ty_limbs.
    CLASS-METHODS to_little
      IMPORTING it_limbs       TYPE ty_limbs
      RETURNING VALUE(rv_data) TYPE xstring.
    CLASS-METHODS modulus
      RETURNING VALUE(rt_modulus) TYPE ty_limbs.
    CLASS-METHODS compare
      IMPORTING
        it_a                      TYPE ty_limbs
        it_b                      TYPE ty_limbs
      RETURNING VALUE(rv_compare) TYPE i.
    CLASS-METHODS subtract
      IMPORTING
        it_a                     TYPE ty_limbs
        it_b                     TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS reduce
      IMPORTING it_value         TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS add_limbs
      IMPORTING
        it_a                     TYPE ty_limbs
        it_b                     TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS multiply_mod
      IMPORTING
        it_a                     TYPE ty_limbs
        it_b                     TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
ENDCLASS.


CLASS zcl_oassh_poly1305 IMPLEMENTATION.
  METHOD from_little.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_accumulator TYPE i.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE i VALUE 1.
* lv_factor tracks 2^lv_bits incrementally; it peaks at 2^20 and the
* accumulator below 2^21, both far inside the signed 32-bit range.
    DO xstrlen( iv_data ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_data+lv_offset(1).
      lv_accumulator = lv_accumulator + lv_byte * lv_factor.
      lv_bits = lv_bits + 8.
      lv_factor = lv_factor * 256.
      WHILE lv_bits >= 13.
        APPEND lv_accumulator MOD c_base TO rt_limbs.
        lv_accumulator = lv_accumulator DIV c_base.
        lv_bits = lv_bits - 13.
        lv_factor = lv_factor DIV c_base.
      ENDWHILE.
    ENDDO.
    IF lv_bits > 0.
      APPEND lv_accumulator TO rt_limbs.
    ENDIF.
  ENDMETHOD.


  METHOD to_little.
    DATA lv_accumulator TYPE i.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_limb TYPE i.
    LOOP AT it_limbs INTO lv_limb.
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
      lv_accumulator = lv_accumulator + lv_limb * lv_factor.
      lv_bits = lv_bits + 13.
      WHILE lv_bits >= 8.
        lv_byte = lv_accumulator MOD 256.
        CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
        lv_accumulator = lv_accumulator DIV 256.
        lv_bits = lv_bits - 8.
      ENDWHILE.
    ENDLOOP.
    IF lv_bits > 0.
      lv_byte = lv_accumulator.
      CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
    ENDIF.
  ENDMETHOD.


  METHOD modulus.
* 2^130 - 5 in base 2^13, least-significant limb first, built once; reduce
* requests it after every block.
    IF gt_modulus IS INITIAL.
      APPEND 8187 TO gt_modulus.
      DO c_limb_count - 1 TIMES.
        APPEND 8191 TO gt_modulus.
      ENDDO.
    ENDIF.
    rt_modulus = gt_modulus.
  ENDMETHOD.


  METHOD compare.
    DATA lv_index TYPE i.
    lv_index = c_limb_count.
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


  METHOD subtract.
    DATA lv_index TYPE i.
    DATA lv_value TYPE i.
    DATA lv_borrow TYPE i.
    rt_result = it_a.
    DO c_limb_count TIMES.
      lv_index = sy-index.
      lv_value = rt_result[ lv_index ] - it_b[ lv_index ] - lv_borrow.
      IF lv_value < 0.
        lv_value = lv_value + c_base.
        lv_borrow = 1.
      ELSE.
        CLEAR lv_borrow.
      ENDIF.
      rt_result[ lv_index ] = lv_value.
    ENDDO.
    ASSERT lv_borrow = 0.
  ENDMETHOD.


  METHOD reduce.
    DATA lv_index TYPE i.
    DATA lv_low_index TYPE i.
    DATA lv_high TYPE i.
    DATA lv_value TYPE i.
    DATA lv_carry TYPE i.
    DATA lt_modulus TYPE ty_limbs.
    rt_result = it_value.
    WHILE lines( rt_result ) < c_limb_count.
      APPEND 0 TO rt_result.
    ENDWHILE.
* Propagate carries over the full convolution first so every limb drops
* below the base; folding a raw convolution limb (up to 10 * 2^14 * 2^13)
* by 5 would overflow the signed 32-bit range.
    CLEAR lv_carry.
    DO lines( rt_result ) TIMES.
      lv_index = sy-index.
      lv_value = rt_result[ lv_index ] + lv_carry.
      rt_result[ lv_index ] = lv_value MOD c_base.
      lv_carry = lv_value DIV c_base.
    ENDDO.
    WHILE lv_carry > 0.
      APPEND lv_carry MOD c_base TO rt_result.
      lv_carry = lv_carry DIV c_base.
    ENDWHILE.
* base^10 = 2^130 is congruent to 5 modulo 2^130-5.
    lv_index = lines( rt_result ).
    WHILE lv_index > c_limb_count.
      lv_high = rt_result[ lv_index ].
      DELETE rt_result INDEX lv_index.
      lv_low_index = lv_index - c_limb_count.
      rt_result[ lv_low_index ] = rt_result[ lv_low_index ] + 5 * lv_high.
      lv_index = lv_index - 1.
    ENDWHILE.
    DO.
      CLEAR lv_carry.
      DO c_limb_count TIMES.
        lv_index = sy-index.
        lv_value = rt_result[ lv_index ] + lv_carry.
        rt_result[ lv_index ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      IF lv_carry = 0.
        EXIT.
      ENDIF.
      rt_result[ 1 ] = rt_result[ 1 ] + 5 * lv_carry.
    ENDDO.
    lt_modulus = modulus( ).
    WHILE compare(
        it_a = rt_result
        it_b = lt_modulus ) >= 0.
      rt_result = subtract(
        it_a = rt_result
        it_b = lt_modulus ).
    ENDWHILE.
  ENDMETHOD.


  METHOD add_limbs.
* The sum stays unreduced: both inputs carry limbs below 2^13, so each sum
* limb is below 2^14 and the following multiply_mod accumulation peaks at
* 10 * 2^14 * 2^13, inside the signed 32-bit range. multiply_mod reduces
* its product, so no separate reduction pass is needed here.
    DATA lv_index TYPE i.
    DO c_limb_count TIMES.
      lv_index = sy-index.
      APPEND it_a[ lv_index ] + it_b[ lv_index ] TO rt_result.
    ENDDO.
  ENDMETHOD.


  METHOD multiply_mod.
    DATA lv_i TYPE i.
    DATA lv_j TYPE i.
    DATA lv_position TYPE i.
    DO c_limb_count * 2 - 1 TIMES.
      APPEND 0 TO rt_result.
    ENDDO.
    DO c_limb_count TIMES.
      lv_i = sy-index.
      DO c_limb_count TIMES.
        lv_j = sy-index.
        lv_position = lv_i + lv_j - 1.
        rt_result[ lv_position ] = rt_result[ lv_position ]
          + it_a[ lv_i ] * it_b[ lv_j ].
      ENDDO.
    ENDDO.
    rt_result = reduce( rt_result ).
  ENDMETHOD.


  METHOD auth.
    DATA lv_r TYPE xstring.
    DATA lv_r_clamped TYPE xstring.
    DATA lv_s TYPE xstring.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_acc_byte TYPE x LENGTH 1.
    DATA lv_s_byte TYPE x LENGTH 1.
    DATA lv_out TYPE x LENGTH 1.
    DATA lv_value TYPE i.
    DATA lv_offset TYPE i.
    DATA lv_length TYPE i.
    DATA lv_block TYPE xstring.
    DATA lv_one TYPE xstring VALUE '01'.
    DATA lv_zero TYPE xstring VALUE '00'.
    DATA lv_acc_bytes TYPE xstring.
    DATA lv_carry TYPE i.
    DATA lt_r TYPE ty_limbs.
    DATA lt_acc TYPE ty_limbs.
    DATA lt_block TYPE ty_limbs.
    ASSERT xstrlen( iv_key ) = 32.
    lv_r = iv_key(16).
    lv_s = iv_key+16(16).
* Clamp r exactly as specified by RFC 8439 section 2.5. Build a new xstring
* because offset writes into variable-length byte strings are not portable.
    DO 16 TIMES.
      lv_offset = sy-index - 1.
      lv_byte = lv_r+lv_offset(1).
      CASE lv_offset.
        WHEN 3 OR 7 OR 11 OR 15.
          lv_value = lv_byte MOD 16.
          lv_byte = lv_value.
        WHEN 4 OR 8 OR 12.
          lv_value = ( lv_byte DIV 4 ) * 4.
          lv_byte = lv_value.
      ENDCASE.
      CONCATENATE lv_r_clamped lv_byte INTO lv_r_clamped IN BYTE MODE.
    ENDDO.
    lt_r = reduce( from_little( lv_r_clamped ) ).
    DO c_limb_count TIMES.
      APPEND 0 TO lt_acc.
    ENDDO.

    CLEAR lv_offset.
    WHILE xstrlen( iv_data ) > lv_offset.
      lv_length = xstrlen( iv_data ) - lv_offset.
      IF lv_length > 16.
        lv_length = 16.
      ENDIF.
      lv_block = iv_data+lv_offset(lv_length).
      CONCATENATE lv_block lv_one INTO lv_block IN BYTE MODE.
      lt_block = from_little( lv_block ).
      WHILE lines( lt_block ) < c_limb_count.
        APPEND 0 TO lt_block.
      ENDWHILE.
      lt_acc = add_limbs(
        it_a = lt_acc
        it_b = lt_block ).
      lt_acc = multiply_mod(
        it_a = lt_acc
        it_b = lt_r ).
      lv_offset = lv_offset + lv_length.
    ENDWHILE.

    lv_acc_bytes = to_little( lt_acc ).
    WHILE xstrlen( lv_acc_bytes ) < 16.
      CONCATENATE lv_acc_bytes lv_zero INTO lv_acc_bytes IN BYTE MODE.
    ENDWHILE.
* Add s modulo 2^128 and emit the low 16 bytes in little-endian order.
    DO 16 TIMES.
      lv_offset = sy-index - 1.
      lv_acc_byte = lv_acc_bytes+lv_offset(1).
      lv_s_byte = lv_s+lv_offset(1).
      lv_value = lv_acc_byte + lv_s_byte + lv_carry.
      lv_out = lv_value MOD 256.
      lv_carry = lv_value DIV 256.
      CONCATENATE rv_tag lv_out INTO rv_tag IN BYTE MODE.
    ENDDO.
  ENDMETHOD.
ENDCLASS.
