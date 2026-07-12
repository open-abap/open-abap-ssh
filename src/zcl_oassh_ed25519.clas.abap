CLASS zcl_oassh_ed25519 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* Pure Ed25519 verification from RFC 8032. Field limbs use base 2^10 so
* every intermediate remains inside ABAP's signed 32-bit integer range.
    CLASS-METHODS verify
      IMPORTING
        iv_public_key TYPE xstring
        iv_message    TYPE xstring
        iv_signature  TYPE xstring
      RETURNING VALUE(rv_verified) TYPE abap_bool.
    CLASS-METHODS public_key
      IMPORTING iv_seed TYPE xstring
      RETURNING VALUE(rv_public_key) TYPE xstring.
    CLASS-METHODS sign_message
      IMPORTING
        iv_seed TYPE xstring
        iv_message TYPE xstring
      RETURNING VALUE(rv_signature) TYPE xstring.
  PRIVATE SECTION.
    TYPES ty_field TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    TYPES:
      BEGIN OF ty_point,
        x TYPE ty_field,
        y TYPE ty_field,
        z TYPE ty_field,
        t TYPE ty_field,
      END OF ty_point.
    CONSTANTS c_base TYPE i VALUE 1024.
    CONSTANTS c_limbs TYPE i VALUE 26.
    CONSTANTS c_l TYPE xstring VALUE
      '1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED'.
    CONSTANTS c_d TYPE xstring VALUE
      '52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3'.
    CONSTANTS c_sqrt_m1 TYPE xstring VALUE
      '2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0'.
    CONSTANTS c_sqrt_exp TYPE xstring VALUE
      '0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE'.
    CONSTANTS c_base_x TYPE xstring VALUE
      '216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A'.
    CONSTANTS c_base_y TYPE xstring VALUE
      '6666666666666666666666666666666666666666666666666666666666666658'.
    CLASS-METHODS reverse_bytes
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rv_data) TYPE xstring.
    CLASS-METHODS field_from_little
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_from_big
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_to_little
      IMPORTING it_field TYPE ty_field
      RETURNING VALUE(rv_data) TYPE xstring.
    CLASS-METHODS field_modulus
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_normalize
      IMPORTING it_field TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_compare
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rv_compare) TYPE i.
    CLASS-METHODS field_sub_raw
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_add
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_sub
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_mul
      IMPORTING
        it_a TYPE ty_field
        it_b TYPE ty_field
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_pow
      IMPORTING
        it_base TYPE ty_field
        iv_exp TYPE xstring
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS field_one
      RETURNING VALUE(rt_field) TYPE ty_field.
    CLASS-METHODS point_base
      RETURNING VALUE(rs_point) TYPE ty_point.
    CLASS-METHODS point_add
      IMPORTING
        is_a TYPE ty_point
        is_b TYPE ty_point
      RETURNING VALUE(rs_point) TYPE ty_point.
    CLASS-METHODS point_mul
      IMPORTING
        iv_scalar TYPE xstring
        is_point TYPE ty_point
      RETURNING VALUE(rs_point) TYPE ty_point.
    CLASS-METHODS point_equal
      IMPORTING
        is_a TYPE ty_point
        is_b TYPE ty_point
      RETURNING VALUE(rv_equal) TYPE abap_bool.
    CLASS-METHODS point_small_order
      IMPORTING is_point TYPE ty_point
      RETURNING VALUE(rv_small) TYPE abap_bool.
    CLASS-METHODS point_encode
      IMPORTING is_point TYPE ty_point
      RETURNING VALUE(rv_encoded) TYPE xstring.
    CLASS-METHODS secret_scalar
      IMPORTING iv_hash TYPE xstring
      RETURNING VALUE(rv_scalar) TYPE xstring.
    CLASS-METHODS point_decode
      IMPORTING iv_encoded TYPE xstring
      EXPORTING
        es_point TYPE ty_point
        ev_valid TYPE abap_bool.
ENDCLASS.


CLASS zcl_oassh_ed25519 IMPLEMENTATION.
  METHOD reverse_bytes.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DO xstrlen( iv_data ) TIMES.
      lv_offset = xstrlen( iv_data ) - sy-index.
      lv_byte = iv_data+lv_offset(1).
      CONCATENATE rv_data lv_byte INTO rv_data IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD field_from_little.
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


  METHOD field_from_big.
    rt_field = field_from_little( reverse_bytes( iv_data ) ).
  ENDMETHOD.


  METHOD field_to_little.
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


  METHOD field_modulus.
    APPEND 1005 TO rt_field.
    DO 24 TIMES.
      APPEND 1023 TO rt_field.
    ENDDO.
    APPEND 31 TO rt_field.
  ENDMETHOD.


  METHOD field_compare.
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


  METHOD field_sub_raw.
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


  METHOD field_normalize.
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
    lt_p = field_modulus( ).
    IF field_compare( it_a = rt_field
                      it_b = lt_p ) >= 0.
      rt_field = field_sub_raw( it_a = rt_field
                                it_b = lt_p ).
    ENDIF.
  ENDMETHOD.


  METHOD field_add.
    DATA lv_index TYPE i.
    DO c_limbs TIMES.
      lv_index = sy-index.
      APPEND it_a[ lv_index ] + it_b[ lv_index ] TO rt_field.
    ENDDO.
    rt_field = field_normalize( rt_field ).
  ENDMETHOD.


  METHOD field_sub.
    DATA lt_p TYPE ty_field.
    DATA lt_sum TYPE ty_field.
    DATA lv_index TYPE i.
    IF field_compare( it_a = it_a
                      it_b = it_b ) >= 0.
      rt_field = field_sub_raw( it_a = it_a
                                it_b = it_b ).
    ELSE.
      lt_p = field_modulus( ).
      DO c_limbs TIMES.
        lv_index = sy-index.
        APPEND it_a[ lv_index ] + lt_p[ lv_index ] TO lt_sum.
      ENDDO.
      rt_field = field_sub_raw( it_a = lt_sum
                                it_b = it_b ).
    ENDIF.
    rt_field = field_normalize( rt_field ).
  ENDMETHOD.


  METHOD field_mul.
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
    rt_field = field_normalize( rt_field ).
  ENDMETHOD.


  METHOD field_one.
    APPEND 1 TO rt_field.
    DO c_limbs - 1 TIMES.
      APPEND 0 TO rt_field.
    ENDDO.
  ENDMETHOD.


  METHOD field_pow.
    DATA lv_offset TYPE i.
    DATA lv_bit_index TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.
    rt_field = field_one( ).
    DO xstrlen( iv_exp ) * 8 TIMES.
      lv_offset = ( sy-index - 1 ) DIV 8.
      lv_bit_index = ( sy-index - 1 ) MOD 8 + 1.
      lv_byte = iv_exp+lv_offset(1).
      GET BIT lv_bit_index OF lv_byte INTO lv_bit.
      rt_field = field_mul( it_a = rt_field
                            it_b = rt_field ).
      IF lv_bit = '1'.
        rt_field = field_mul( it_a = rt_field
                              it_b = it_base ).
      ENDIF.
    ENDDO.
  ENDMETHOD.


  METHOD point_base.
    rs_point-x = field_from_big( c_base_x ).
    rs_point-y = field_from_big( c_base_y ).
    rs_point-z = field_one( ).
    rs_point-t = field_mul( it_a = rs_point-x
                            it_b = rs_point-y ).
  ENDMETHOD.


  METHOD point_add.
    DATA lt_a TYPE ty_field.
    DATA lt_b TYPE ty_field.
    DATA lt_c TYPE ty_field.
    DATA lt_d TYPE ty_field.
    DATA lt_e TYPE ty_field.
    DATA lt_f TYPE ty_field.
    DATA lt_g TYPE ty_field.
    DATA lt_h TYPE ty_field.
    DATA lt_two TYPE ty_field.
    DATA lt_curve_d TYPE ty_field.
    lt_two = field_one( ).
    lt_two = field_add( it_a = lt_two
                        it_b = lt_two ).
    lt_curve_d = field_from_big( c_d ).
    lt_a = field_mul(
      it_a = field_sub( it_a = is_a-y it_b = is_a-x )
      it_b = field_sub( it_a = is_b-y it_b = is_b-x ) ).
    lt_b = field_mul(
      it_a = field_add( it_a = is_a-y it_b = is_a-x )
      it_b = field_add( it_a = is_b-y it_b = is_b-x ) ).
    lt_c = field_mul(
      it_a = field_mul( it_a = is_a-t it_b = lt_two )
      it_b = field_mul( it_a = lt_curve_d it_b = is_b-t ) ).
    lt_d = field_mul(
      it_a = field_mul( it_a = is_a-z it_b = lt_two )
      it_b = is_b-z ).
    lt_e = field_sub( it_a = lt_b
                      it_b = lt_a ).
    lt_f = field_sub( it_a = lt_d
                      it_b = lt_c ).
    lt_g = field_add( it_a = lt_d
                      it_b = lt_c ).
    lt_h = field_add( it_a = lt_b
                      it_b = lt_a ).
    rs_point-x = field_mul( it_a = lt_e
                            it_b = lt_f ).
    rs_point-y = field_mul( it_a = lt_g
                            it_b = lt_h ).
    rs_point-t = field_mul( it_a = lt_e
                            it_b = lt_h ).
    rs_point-z = field_mul( it_a = lt_f
                            it_b = lt_g ).
  ENDMETHOD.


  METHOD point_mul.
    DATA ls_addend TYPE ty_point.
    DATA lv_offset TYPE i.
    DATA lv_bit_index TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.
    rs_point-x = field_normalize( VALUE ty_field( ) ).
    rs_point-y = field_one( ).
    rs_point-z = field_one( ).
    rs_point-t = field_normalize( VALUE ty_field( ) ).
    ls_addend = is_point.
    DO xstrlen( iv_scalar ) * 8 TIMES.
      lv_offset = xstrlen( iv_scalar ) - 1 - ( ( sy-index - 1 ) DIV 8 ).
      lv_bit_index = 8 - ( ( sy-index - 1 ) MOD 8 ).
      lv_byte = iv_scalar+lv_offset(1).
      GET BIT lv_bit_index OF lv_byte INTO lv_bit.
      IF lv_bit = '1'.
        rs_point = point_add( is_a = rs_point
                              is_b = ls_addend ).
      ENDIF.
      ls_addend = point_add( is_a = ls_addend
                             is_b = ls_addend ).
    ENDDO.
  ENDMETHOD.


  METHOD point_equal.
    DATA lt_left TYPE ty_field.
    DATA lt_right TYPE ty_field.
    lt_left = field_mul( it_a = is_a-x
                         it_b = is_b-z ).
    lt_right = field_mul( it_a = is_b-x
                          it_b = is_a-z ).
    IF field_compare( it_a = lt_left
                      it_b = lt_right ) <> 0.
      RETURN.
    ENDIF.
    lt_left = field_mul( it_a = is_a-y
                         it_b = is_b-z ).
    lt_right = field_mul( it_a = is_b-y
                          it_b = is_a-z ).
    rv_equal = xsdbool( field_compare( it_a = lt_left
                                       it_b = lt_right ) = 0 ).
  ENDMETHOD.


  METHOD point_small_order.
    DATA ls_point TYPE ty_point.
    DATA ls_neutral TYPE ty_point.
    ls_point = is_point.
    DO 3 TIMES.
      ls_point = point_add(
        is_a = ls_point
        is_b = ls_point ).
    ENDDO.
    ls_neutral-x = field_normalize( VALUE ty_field( ) ).
    ls_neutral-y = field_one( ).
    ls_neutral-z = field_one( ).
    ls_neutral-t = field_normalize( VALUE ty_field( ) ).
    rv_small = point_equal(
      is_a = ls_point
      is_b = ls_neutral ).
  ENDMETHOD.


  METHOD point_encode.
    DATA lt_z_inverse TYPE ty_field.
    DATA lt_x TYPE ty_field.
    DATA lt_y TYPE ty_field.
    DATA lv_y TYPE xstring.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_out TYPE x LENGTH 1.
    lt_z_inverse = field_pow(
      it_base = is_point-z
      iv_exp  = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB' ).
    lt_x = field_mul(
      it_a = is_point-x
      it_b = lt_z_inverse ).
    lt_y = field_mul(
      it_a = is_point-y
      it_b = lt_z_inverse ).
    lv_y = field_to_little( lt_y ).
    DO 32 TIMES.
      lv_offset = sy-index - 1.
      lv_byte = lv_y+lv_offset(1).
      lv_out = lv_byte.
      IF lv_offset = 31 AND lt_x[ 1 ] MOD 2 = 1.
        lv_out = lv_byte + 128.
      ENDIF.
      CONCATENATE rv_encoded lv_out INTO rv_encoded IN BYTE MODE.
    ENDDO.
  ENDMETHOD.


  METHOD secret_scalar.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_out TYPE x LENGTH 1.
    DATA lv_little TYPE xstring.
    ASSERT xstrlen( iv_hash ) = 64.
    DO 32 TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_hash+lv_offset(1).
      lv_out = lv_byte.
      CASE lv_offset.
        WHEN 0.
          lv_out = ( lv_byte DIV 8 ) * 8.
        WHEN 31.
          lv_out = lv_byte MOD 64 + 64.
      ENDCASE.
      CONCATENATE lv_little lv_out INTO lv_little IN BYTE MODE.
    ENDDO.
    rv_scalar = reverse_bytes( lv_little ).
  ENDMETHOD.


  METHOD point_decode.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_clean_byte TYPE x LENGTH 1.
    DATA lv_clean TYPE xstring.
    DATA lv_sign TYPE i.
    DATA lt_p TYPE ty_field.
    DATA lt_one TYPE ty_field.
    DATA lt_y2 TYPE ty_field.
    DATA lt_u TYPE ty_field.
    DATA lt_v TYPE ty_field.
    DATA lt_x2 TYPE ty_field.
    DATA lt_x TYPE ty_field.
    DATA lt_check TYPE ty_field.
    DATA lt_zero TYPE ty_field.
    IF xstrlen( iv_encoded ) <> 32.
      RETURN.
    ENDIF.
    DO 32 TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_encoded+lv_offset(1).
      lv_clean_byte = lv_byte.
      IF lv_offset = 31.
        lv_sign = lv_byte DIV 128.
        lv_clean_byte = lv_byte MOD 128.
      ENDIF.
      CONCATENATE lv_clean lv_clean_byte INTO lv_clean IN BYTE MODE.
    ENDDO.
    es_point-y = field_from_little( lv_clean ).
    lt_p = field_modulus( ).
    IF field_compare( it_a = es_point-y
                      it_b = lt_p ) >= 0.
      RETURN.
    ENDIF.
    lt_one = field_one( ).
    lt_y2 = field_mul( it_a = es_point-y
                       it_b = es_point-y ).
    lt_u = field_sub( it_a = lt_y2
                      it_b = lt_one ).
    lt_v = field_add(
      it_a = field_mul( it_a = field_from_big( c_d ) it_b = lt_y2 )
      it_b = lt_one ).
    lt_x2 = field_mul(
      it_a = lt_u
      it_b = field_pow( it_base = lt_v iv_exp = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB' ) ).
    lt_x = field_pow( it_base = lt_x2
                      iv_exp  = c_sqrt_exp ).
    lt_check = field_mul( it_a = lt_x
                          it_b = lt_x ).
    IF field_compare( it_a = lt_check
                      it_b = lt_x2 ) <> 0.
      lt_x = field_mul( it_a = lt_x
                        it_b = field_from_big( c_sqrt_m1 ) ).
      lt_check = field_mul( it_a = lt_x
                            it_b = lt_x ).
      IF field_compare( it_a = lt_check
                        it_b = lt_x2 ) <> 0.
        RETURN.
      ENDIF.
    ENDIF.
    lt_zero = field_normalize( VALUE ty_field( ) ).
    IF field_compare( it_a = lt_x
                      it_b = lt_zero ) = 0 AND lv_sign = 1.
      RETURN.
    ENDIF.
    IF lt_x[ 1 ] MOD 2 <> lv_sign.
      lt_x = field_sub( it_a = lt_p
                        it_b = lt_x ).
    ENDIF.
    es_point-x = lt_x.
    es_point-z = lt_one.
    es_point-t = field_mul( it_a = es_point-x
                            it_b = es_point-y ).
    ev_valid = abap_true.
  ENDMETHOD.


  METHOD verify.
    DATA lv_r_encoded TYPE xstring.
    DATA lv_s_little TYPE xstring.
    DATA lv_s TYPE xstring.
    DATA lv_hash_input TYPE xstring.
    DATA lv_hash TYPE xstring.
    DATA lv_h TYPE xstring.
    DATA lv_valid_a TYPE abap_bool.
    DATA lv_valid_r TYPE abap_bool.
    DATA ls_a TYPE ty_point.
    DATA ls_r TYPE ty_point.
    DATA ls_left TYPE ty_point.
    DATA ls_right TYPE ty_point.
    DATA ls_h_a TYPE ty_point.
    IF xstrlen( iv_public_key ) <> 32 OR xstrlen( iv_signature ) <> 64.
      RETURN.
    ENDIF.
    lv_r_encoded = iv_signature(32).
    lv_s_little = iv_signature+32(32).
    lv_s = reverse_bytes( lv_s_little ).
    IF zcl_oassh_bigint=>compare( iv_a = lv_s
                                  iv_b = c_l ) >= 0.
      RETURN.
    ENDIF.
    point_decode(
      EXPORTING iv_encoded = iv_public_key
      IMPORTING
        es_point           = ls_a
        ev_valid           = lv_valid_a ).
    point_decode(
      EXPORTING iv_encoded = lv_r_encoded
      IMPORTING
        es_point           = ls_r
        ev_valid           = lv_valid_r ).
    IF lv_valid_a = abap_false OR lv_valid_r = abap_false.
      RETURN.
    ENDIF.
    IF point_small_order( ls_a ) = abap_true
        OR point_small_order( ls_r ) = abap_true.
      RETURN.
    ENDIF.
    CONCATENATE lv_r_encoded iv_public_key iv_message
      INTO lv_hash_input IN BYTE MODE.
    lv_hash = zcl_oassh_sha512=>hash( lv_hash_input ).
    lv_h = zcl_oassh_bigint=>modulo(
      iv_a = reverse_bytes( lv_hash )
      iv_m = c_l ).
    ls_left = point_mul( iv_scalar = lv_s
                         is_point  = point_base( ) ).
    ls_h_a = point_mul( iv_scalar = lv_h
                        is_point  = ls_a ).
    ls_right = point_add( is_a = ls_r
                          is_b = ls_h_a ).
* RFC 8032's cofactored verification equation.
    DO 3 TIMES.
      ls_left = point_add( is_a = ls_left
                           is_b = ls_left ).
      ls_right = point_add( is_a = ls_right
                            is_b = ls_right ).
    ENDDO.
    rv_verified = point_equal( is_a = ls_left
                               is_b = ls_right ).
  ENDMETHOD.


  METHOD public_key.
    DATA lv_hash TYPE xstring.
    DATA lv_scalar TYPE xstring.
    ASSERT xstrlen( iv_seed ) = 32.
    lv_hash = zcl_oassh_sha512=>hash( iv_seed ).
    lv_scalar = secret_scalar( lv_hash ).
    rv_public_key = point_encode(
      point_mul(
        iv_scalar = lv_scalar
        is_point  = point_base( ) ) ).
  ENDMETHOD.


  METHOD sign_message.
    DATA lv_hash TYPE xstring.
    DATA lv_scalar TYPE xstring.
    DATA lv_prefix TYPE xstring.
    DATA lv_nonce_input TYPE xstring.
    DATA lv_nonce_hash TYPE xstring.
    DATA lv_r TYPE xstring.
    DATA lv_r_encoded TYPE xstring.
    DATA lv_public_key TYPE xstring.
    DATA lv_challenge_input TYPE xstring.
    DATA lv_k TYPE xstring.
    DATA lv_s TYPE xstring.
    DATA lv_s_little TYPE xstring.
    DATA lv_zero TYPE x LENGTH 1 VALUE '00'.
    ASSERT xstrlen( iv_seed ) = 32.
    lv_hash = zcl_oassh_sha512=>hash( iv_seed ).
    lv_scalar = secret_scalar( lv_hash ).
    lv_prefix = lv_hash+32(32).
    CONCATENATE lv_prefix iv_message INTO lv_nonce_input IN BYTE MODE.
    lv_nonce_hash = zcl_oassh_sha512=>hash( lv_nonce_input ).
    lv_r = zcl_oassh_bigint=>modulo(
      iv_a = reverse_bytes( lv_nonce_hash )
      iv_m = c_l ).
    lv_r_encoded = point_encode(
      point_mul(
        iv_scalar = lv_r
        is_point  = point_base( ) ) ).
    lv_public_key = point_encode(
      point_mul(
        iv_scalar = lv_scalar
        is_point  = point_base( ) ) ).
    CONCATENATE lv_r_encoded lv_public_key iv_message
      INTO lv_challenge_input IN BYTE MODE.
    lv_k = zcl_oassh_bigint=>modulo(
      iv_a = reverse_bytes( zcl_oassh_sha512=>hash( lv_challenge_input ) )
      iv_m = c_l ).
    lv_s = zcl_oassh_bigint=>modulo(
      iv_a = zcl_oassh_bigint=>add(
        iv_a = lv_r
        iv_b = zcl_oassh_bigint=>multiply(
          iv_a = lv_k
          iv_b = lv_scalar ) )
      iv_m = c_l ).
    lv_s_little = reverse_bytes( lv_s ).
    WHILE xstrlen( lv_s_little ) < 32.
      CONCATENATE lv_s_little lv_zero INTO lv_s_little IN BYTE MODE.
    ENDWHILE.
    CONCATENATE lv_r_encoded lv_s_little INTO rv_signature IN BYTE MODE.
  ENDMETHOD.
ENDCLASS.
