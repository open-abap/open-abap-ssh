CLASS zcl_oassh_field25519 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* Arithmetic in GF(2^255 - 19), the shared prime field of Curve25519 and
* Ed25519. Elements are 10 little-endian limbs of base 2^26 held in int8,
* so a schoolbook multiply term stays below 2^56 and the folding reduction
* stays inside the signed 64-bit range. This is the field layer for
* zcl_oassh_x25519; the implementation is the one proven by the Ed25519
* RFC 8032 vectors and can also back zcl_oassh_ed25519.

    TYPES ty_field TYPE STANDARD TABLE OF int8 WITH EMPTY KEY.

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
    CLASS-METHODS sqr
      IMPORTING it_a TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS inv
      IMPORTING it_a TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS one
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS zero
      RETURNING VALUE(rt_field) TYPE ty_field.

  PRIVATE SECTION.
    CONSTANTS c_base TYPE i VALUE 67108864.
* the top limb only spans bits 234..254 of p, 21 bits
    CONSTANTS c_top TYPE i VALUE 2097152.
    CONSTANTS c_limbs TYPE i VALUE 10.

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
    CLASS-METHODS sqr_times
      IMPORTING
        it_a TYPE ty_field
        iv_count TYPE i
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
    DATA lv_acc TYPE int8.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE int8 VALUE 1.
    DO xstrlen( iv_data ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_data+lv_offset(1).
      lv_acc = lv_acc + lv_byte * lv_factor.
      lv_bits = lv_bits + 8.
      lv_factor = lv_factor * 256.
      WHILE lv_bits >= 26.
        APPEND lv_acc MOD c_base TO rt_field.
        lv_acc = lv_acc DIV c_base.
        lv_bits = lv_bits - 26.
        lv_factor = lv_factor DIV c_base.
      ENDWHILE.
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
    DATA lv_acc TYPE int8.
    DATA lv_bits TYPE i.
    DATA lv_factor TYPE int8.
    DATA lv_limb TYPE int8.
    DATA lv_low TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_zero TYPE x LENGTH 1 VALUE '00'.
    LOOP AT it_field INTO lv_limb.
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
      lv_acc = lv_acc + lv_limb * lv_factor.
      lv_bits = lv_bits + 26.
      WHILE lv_bits >= 8.
        lv_low = lv_acc MOD 256.
        lv_byte = lv_low.
        CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
        lv_acc = lv_acc DIV 256.
        lv_bits = lv_bits - 8.
      ENDWHILE.
    ENDLOOP.
    IF lv_acc > 0.
      lv_low = lv_acc.
      lv_byte = lv_low.
      CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
    ENDIF.
    WHILE xstrlen( rv_data ) < 32.
      CONCATENATE rv_data lv_zero INTO rv_data IN BYTE MODE.
    ENDWHILE.
  ENDMETHOD.


  METHOD modulus.
* p = 2^255 - 19: low limb 2^26 - 19, middle limbs full, top limb 2^21 - 1
    APPEND 67108845 TO rt_field.
    DO c_limbs - 2 TIMES.
      APPEND 67108863 TO rt_field.
    ENDDO.
    APPEND 2097151 TO rt_field.
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
    DATA lv_value TYPE int8.
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
    DATA lv_value TYPE int8.
    DATA lv_carry TYPE int8.
    DATA lv_high TYPE int8.
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
      lv_high = rt_field[ c_limbs ] DIV c_top.
      rt_field[ c_limbs ] = rt_field[ c_limbs ] MOD c_top.
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
    DATA lv_a TYPE int8.
    DO c_limbs * 2 - 1 TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
    DO c_limbs TIMES.
      lv_i = sy-index.
      lv_a = it_a[ lv_i ].
      DO c_limbs TIMES.
        lv_j = sy-index.
        lv_position = lv_i + lv_j - 1.
        rt_field[ lv_position ] = rt_field[ lv_position ]
          + lv_a * it_b[ lv_j ].
      ENDDO.
    ENDDO.
    rt_field = normalize( rt_field ).
  ENDMETHOD.


  METHOD sqr.
* Schoolbook squaring: each cross product appears twice, so only the
* upper triangle is walked and off-diagonal terms are doubled.
    DATA lv_i TYPE i.
    DATA lv_j TYPE i.
    DATA lv_position TYPE i.
    DATA lv_a TYPE int8.
    DO c_limbs * 2 - 1 TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
    DO c_limbs TIMES.
      lv_i = sy-index.
      lv_a = it_a[ lv_i ].
      lv_position = lv_i * 2 - 1.
      rt_field[ lv_position ] = rt_field[ lv_position ] + lv_a * lv_a.
      lv_a = lv_a * 2.
      lv_j = lv_i + 1.
      WHILE lv_j <= c_limbs.
        lv_position = lv_i + lv_j - 1.
        rt_field[ lv_position ] = rt_field[ lv_position ]
          + lv_a * it_a[ lv_j ].
        lv_j = lv_j + 1.
      ENDWHILE.
    ENDDO.
    rt_field = normalize( rt_field ).
  ENDMETHOD.


  METHOD sqr_times.
    rt_field = it_a.
    DO iv_count TIMES.
      rt_field = sqr( rt_field ).
    ENDDO.
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


  METHOD inv.
* Fermat inversion a^(p-2) with p - 2 = 2^255 - 21, using the standard
* Curve25519 addition chain: 254 squarings and 11 multiplies instead of
* generic square-and-multiply over an exponent of mostly one-bits.
    DATA lt_z2 TYPE ty_field.
    DATA lt_z9 TYPE ty_field.
    DATA lt_z11 TYPE ty_field.
    DATA lt_z2_5_0 TYPE ty_field.
    DATA lt_z2_10_0 TYPE ty_field.
    DATA lt_z2_20_0 TYPE ty_field.
    DATA lt_z2_50_0 TYPE ty_field.
    DATA lt_z2_100_0 TYPE ty_field.
    DATA lt_t TYPE ty_field.

    lt_z2 = sqr( it_a ).
    lt_t = sqr( sqr( lt_z2 ) ).
    lt_z9 = mul( it_a = lt_t
                 it_b = it_a ).
    lt_z11 = mul( it_a = lt_z9
                  it_b = lt_z2 ).
    lt_t = sqr( lt_z11 ).
* a^(2^5 - 1)
    lt_z2_5_0 = mul( it_a = lt_t
                     it_b = lt_z9 ).
* a^(2^10 - 1)
    lt_t = sqr_times( it_a     = lt_z2_5_0
                      iv_count = 5 ).
    lt_z2_10_0 = mul( it_a = lt_t
                      it_b = lt_z2_5_0 ).
* a^(2^20 - 1)
    lt_t = sqr_times( it_a     = lt_z2_10_0
                      iv_count = 10 ).
    lt_z2_20_0 = mul( it_a = lt_t
                      it_b = lt_z2_10_0 ).
* a^(2^40 - 1)
    lt_t = sqr_times( it_a     = lt_z2_20_0
                      iv_count = 20 ).
    lt_t = mul( it_a = lt_t
                it_b = lt_z2_20_0 ).
* a^(2^50 - 1)
    lt_t = sqr_times( it_a     = lt_t
                      iv_count = 10 ).
    lt_z2_50_0 = mul( it_a = lt_t
                      it_b = lt_z2_10_0 ).
* a^(2^100 - 1)
    lt_t = sqr_times( it_a     = lt_z2_50_0
                      iv_count = 50 ).
    lt_z2_100_0 = mul( it_a = lt_t
                       it_b = lt_z2_50_0 ).
* a^(2^200 - 1)
    lt_t = sqr_times( it_a     = lt_z2_100_0
                      iv_count = 100 ).
    lt_t = mul( it_a = lt_t
                it_b = lt_z2_100_0 ).
* a^(2^250 - 1)
    lt_t = sqr_times( it_a     = lt_t
                      iv_count = 50 ).
    lt_t = mul( it_a = lt_t
                it_b = lt_z2_50_0 ).
* a^(2^255 - 32) * a^11 = a^(2^255 - 21)
    lt_t = sqr_times( it_a     = lt_t
                      iv_count = 5 ).
    rt_field = mul( it_a = lt_t
                    it_b = lt_z11 ).
  ENDMETHOD.

ENDCLASS.
