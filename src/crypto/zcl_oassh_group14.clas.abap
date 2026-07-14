CLASS zcl_oassh_group14 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* RFC 3526 group 14 arithmetic. Montgomery multiplication uses 15-bit
* limbs so every intermediate stays inside ABAP's signed 32-bit integer.
    CLASS-METHODS prime
      RETURNING VALUE(rv_prime) TYPE xstring.
    CLASS-METHODS public_key
      IMPORTING iv_private       TYPE xstring
      RETURNING VALUE(rv_public) TYPE xstring.
    CLASS-METHODS shared_secret
      IMPORTING
        iv_peer_public           TYPE xstring
        iv_private               TYPE xstring
      RETURNING VALUE(rv_secret) TYPE xstring.
    CLASS-METHODS is_valid_public
      IMPORTING iv_public       TYPE xstring
      RETURNING VALUE(rv_valid) TYPE abap_bool.
  PRIVATE SECTION.
    TYPES ty_limbs TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    CONSTANTS c_base TYPE i VALUE 32768.
    CONSTANTS c_limb_count TYPE i VALUE 137.
    CONSTANTS c_prime_1 TYPE xstring VALUE
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
    CONSTANTS c_prime_2 TYPE xstring VALUE
      'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
    CONSTANTS c_prime_3 TYPE xstring VALUE
      'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
    CONSTANTS c_prime_4 TYPE xstring VALUE
      '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
    CONSTANTS c_prime_5 TYPE xstring VALUE
      'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
    CONSTANTS c_prime_6 TYPE xstring VALUE
      '15728E5A8AACAA68FFFFFFFFFFFFFFFF'.
    CLASS-DATA gt_modulus TYPE ty_limbs.
    CLASS-DATA gt_r_squared TYPE ty_limbs.
    CLASS-DATA gv_initialized TYPE abap_bool.

    CLASS-METHODS initialize.
    CLASS-METHODS mod_pow
      IMPORTING
        iv_base                  TYPE xstring
        iv_exponent              TYPE xstring
      RETURNING VALUE(rv_result) TYPE xstring.
    CLASS-METHODS from_xstring
      IMPORTING iv_value        TYPE xstring
      RETURNING VALUE(rt_limbs) TYPE ty_limbs.
    CLASS-METHODS to_xstring
      IMPORTING it_limbs        TYPE ty_limbs
      RETURNING VALUE(rv_value) TYPE xstring.
    CLASS-METHODS normalize
      CHANGING ct_limbs TYPE ty_limbs.
    CLASS-METHODS pad
      IMPORTING it_limbs        TYPE ty_limbs
      RETURNING VALUE(rt_limbs) TYPE ty_limbs.
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
    CLASS-METHODS double_mod
      IMPORTING it_value         TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS montgomery_multiply
      IMPORTING
        it_a                     TYPE ty_limbs
        it_b                     TYPE ty_limbs
      RETURNING VALUE(rt_result) TYPE ty_limbs.
ENDCLASS.


CLASS zcl_oassh_group14 IMPLEMENTATION.

  METHOD prime.
    CONCATENATE c_prime_1 c_prime_2 c_prime_3 c_prime_4 c_prime_5 c_prime_6
      INTO rv_prime IN BYTE MODE.
  ENDMETHOD.


  METHOD normalize.
    DATA lv_index TYPE i.
    lv_index = lines( ct_limbs ).
    WHILE lv_index > 0 AND ct_limbs[ lv_index ] = 0.
      DELETE ct_limbs INDEX lv_index.
      lv_index = lv_index - 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD pad.
    rt_limbs = it_limbs.
    WHILE lines( rt_limbs ) < c_limb_count.
      APPEND 0 TO rt_limbs.
    ENDWHILE.
  ENDMETHOD.


  METHOD from_xstring.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.
    FIELD-SYMBOLS <lv_limb> TYPE i.

    DO xstrlen( iv_value ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_value+lv_offset(1).
      lv_carry = lv_byte.
      LOOP AT rt_limbs ASSIGNING <lv_limb>.
        lv_value = <lv_limb> * 256 + lv_carry.
        <lv_limb> = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDLOOP.
      WHILE lv_carry > 0.
        APPEND lv_carry MOD c_base TO rt_limbs.
        lv_carry = lv_carry DIV c_base.
      ENDWHILE.
    ENDDO.
    normalize( CHANGING ct_limbs = rt_limbs ).
  ENDMETHOD.


  METHOD to_xstring.
    DATA lt_limbs TYPE ty_limbs.
    DATA lv_index TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.
    DATA lv_byte TYPE x LENGTH 1.

    lt_limbs = it_limbs.
    normalize( CHANGING ct_limbs = lt_limbs ).
    WHILE lines( lt_limbs ) > 0.
      CLEAR lv_carry.
      lv_index = lines( lt_limbs ).
      WHILE lv_index > 0.
        lv_value = lv_carry * c_base + lt_limbs[ lv_index ].
        lt_limbs[ lv_index ] = lv_value DIV 256.
        lv_carry = lv_value MOD 256.
        lv_index = lv_index - 1.
      ENDWHILE.
      lv_byte = lv_carry.
      CONCATENATE lv_byte rv_value INTO rv_value IN BYTE MODE.
      normalize( CHANGING ct_limbs = lt_limbs ).
    ENDWHILE.
  ENDMETHOD.


  METHOD compare.
    DATA lt_a TYPE ty_limbs.
    DATA lt_b TYPE ty_limbs.
    DATA lv_index TYPE i.
    lt_a = it_a.
    lt_b = it_b.
    normalize( CHANGING ct_limbs = lt_a ).
    normalize( CHANGING ct_limbs = lt_b ).
    IF lines( lt_a ) > lines( lt_b ).
      rv_compare = 1.
      RETURN.
    ELSEIF lines( lt_a ) < lines( lt_b ).
      rv_compare = -1.
      RETURN.
    ENDIF.
    lv_index = lines( lt_a ).
    WHILE lv_index > 0.
      IF lt_a[ lv_index ] > lt_b[ lv_index ].
        rv_compare = 1.
        RETURN.
      ELSEIF lt_a[ lv_index ] < lt_b[ lv_index ].
        rv_compare = -1.
        RETURN.
      ENDIF.
      lv_index = lv_index - 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD subtract.
    DATA lv_index TYPE i.
    DATA lv_b TYPE i.
    DATA lv_borrow TYPE i.
    DATA lv_value TYPE i.
    ASSERT compare(
      it_a = it_a
      it_b = it_b ) >= 0.
    rt_result = it_a.
    DO lines( rt_result ) TIMES.
      lv_index = sy-index.
      CLEAR lv_b.
      IF lines( it_b ) >= lv_index.
        lv_b = it_b[ lv_index ].
      ENDIF.
      lv_value = rt_result[ lv_index ] - lv_b - lv_borrow.
      IF lv_value < 0.
        lv_value = lv_value + c_base.
        lv_borrow = 1.
      ELSE.
        CLEAR lv_borrow.
      ENDIF.
      rt_result[ lv_index ] = lv_value.
    ENDDO.
    ASSERT lv_borrow = 0.
    normalize( CHANGING ct_limbs = rt_result ).
  ENDMETHOD.


  METHOD double_mod.
    DATA lv_index TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.
    DO lines( it_value ) TIMES.
      lv_index = sy-index.
      lv_value = it_value[ lv_index ] * 2 + lv_carry.
      APPEND lv_value MOD c_base TO rt_result.
      lv_carry = lv_value DIV c_base.
    ENDDO.
    IF lv_carry > 0.
      APPEND lv_carry TO rt_result.
    ENDIF.
    IF compare(
        it_a = rt_result
        it_b = gt_modulus ) >= 0.
      rt_result = subtract(
        it_a = rt_result
        it_b = gt_modulus ).
    ENDIF.
  ENDMETHOD.


  METHOD initialize.
    DATA lv_iterations TYPE i.
    IF gv_initialized = abap_true.
      RETURN.
    ENDIF.
    gt_modulus = from_xstring( prime( ) ).
    ASSERT lines( gt_modulus ) = c_limb_count.
    APPEND 1 TO gt_r_squared.
    lv_iterations = 2 * c_limb_count * 15.
    DO lv_iterations TIMES.
      gt_r_squared = double_mod( gt_r_squared ).
    ENDDO.
    gv_initialized = abap_true.
  ENDMETHOD.


  METHOD montgomery_multiply.
* REDC with base 2^15. Since group14 ends in all one bits, its least
* significant limb is -1 mod base and -N^-1 is exactly 1.
    DATA lt_a TYPE ty_limbs.
    DATA lt_b TYPE ty_limbs.
    DATA lt_t TYPE ty_limbs.
    DATA lv_i TYPE i.
    DATA lv_j TYPE i.
    DATA lv_position TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.
    DATA lv_m TYPE i.

    lt_a = pad( it_a ).
    lt_b = pad( it_b ).
    DO c_limb_count * 2 + 2 TIMES.
      APPEND 0 TO lt_t.
    ENDDO.

    DO c_limb_count TIMES.
      lv_i = sy-index - 1.
      CLEAR lv_carry.
      DO c_limb_count TIMES.
        lv_j = sy-index - 1.
        lv_position = lv_i + lv_j + 1.
        lv_value = lt_t[ lv_position ]
          + lt_a[ lv_i + 1 ] * lt_b[ lv_j + 1 ] + lv_carry.
        lt_t[ lv_position ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      lv_position = lv_i + c_limb_count + 1.
      WHILE lv_carry > 0.
        lv_value = lt_t[ lv_position ] + lv_carry.
        lt_t[ lv_position ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
        lv_position = lv_position + 1.
      ENDWHILE.
    ENDDO.

    DO c_limb_count TIMES.
      lv_i = sy-index - 1.
      lv_m = lt_t[ lv_i + 1 ].
      CLEAR lv_carry.
      DO c_limb_count TIMES.
        lv_j = sy-index - 1.
        lv_position = lv_i + lv_j + 1.
        lv_value = lt_t[ lv_position ]
          + lv_m * gt_modulus[ lv_j + 1 ] + lv_carry.
        lt_t[ lv_position ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      lv_position = lv_i + c_limb_count + 1.
      WHILE lv_carry > 0.
        lv_value = lt_t[ lv_position ] + lv_carry.
        lt_t[ lv_position ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
        lv_position = lv_position + 1.
      ENDWHILE.
    ENDDO.

    DO c_limb_count + 1 TIMES.
      APPEND lt_t[ c_limb_count + sy-index ] TO rt_result.
    ENDDO.
    normalize( CHANGING ct_limbs = rt_result ).
    IF compare(
        it_a = rt_result
        it_b = gt_modulus ) >= 0.
      rt_result = subtract(
        it_a = rt_result
        it_b = gt_modulus ).
    ENDIF.
  ENDMETHOD.


  METHOD mod_pow.
    DATA lt_base TYPE ty_limbs.
    DATA lt_one TYPE ty_limbs.
    DATA lt_result TYPE ty_limbs.
    DATA lv_offset TYPE i.
    DATA lv_bit_position TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.

    initialize( ).
    lt_base = from_xstring( iv_base ).
    ASSERT compare(
      it_a = lt_base
      it_b = gt_modulus ) < 0.
    APPEND 1 TO lt_one.
    lt_base = montgomery_multiply(
      it_a = lt_base
      it_b = gt_r_squared ).
    lt_result = montgomery_multiply(
      it_a = lt_one
      it_b = gt_r_squared ).

    DO xstrlen( iv_exponent ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_exponent+lv_offset(1).
      DO 8 TIMES.
        lv_bit_position = sy-index.
        lt_result = montgomery_multiply(
          it_a = lt_result
          it_b = lt_result ).
        GET BIT lv_bit_position OF lv_byte INTO lv_bit.
        IF lv_bit = '1'.
          lt_result = montgomery_multiply(
            it_a = lt_result
            it_b = lt_base ).
        ENDIF.
      ENDDO.
    ENDDO.
    lt_result = montgomery_multiply(
      it_a = lt_result
      it_b = lt_one ).
    rv_result = to_xstring( lt_result ).
  ENDMETHOD.


  METHOD public_key.
    ASSERT zcl_oassh_bigint=>compare(
      iv_a = iv_private
      iv_b = '01' ) > 0.
    rv_public = mod_pow(
      iv_base     = '02'
      iv_exponent = iv_private ).
    ASSERT is_valid_public( rv_public ) = abap_true.
  ENDMETHOD.


  METHOD shared_secret.
    ASSERT is_valid_public( iv_peer_public ) = abap_true.
    ASSERT zcl_oassh_bigint=>compare(
      iv_a = iv_private
      iv_b = '01' ) > 0.
    rv_secret = mod_pow(
      iv_base     = iv_peer_public
      iv_exponent = iv_private ).
  ENDMETHOD.


  METHOD is_valid_public.
    DATA lv_maximum TYPE xstring.
    lv_maximum = zcl_oassh_bigint=>subtract(
      iv_a = prime( )
      iv_b = '01' ).
    rv_valid = xsdbool(
      zcl_oassh_bigint=>compare(
        iv_a = iv_public
        iv_b = '01' ) > 0
      AND zcl_oassh_bigint=>compare(
        iv_a = iv_public
        iv_b = lv_maximum ) < 0 ).
  ENDMETHOD.
ENDCLASS.
