CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS add FOR TESTING RAISING cx_static_check.
    METHODS subtract FOR TESTING RAISING cx_static_check.
    METHODS compare FOR TESTING RAISING cx_static_check.
    METHODS multiply FOR TESTING RAISING cx_static_check.
    METHODS modulo FOR TESTING RAISING cx_static_check.
    METHODS mod_pow FOR TESTING RAISING cx_static_check.
    METHODS mod_pow_medium FOR TESTING RAISING cx_static_check.
    METHODS normalize_large_prefix FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD add.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>add( iv_a = 'FF' iv_b = '01' )
      exp = '0100' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>add( iv_a = '123456789A' iv_b = 'FEDCBA' )
      exp = '1235555554' ).

    " leading zeros are normalised away
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>add( iv_a = '0000FF' iv_b = '01' )
      exp = '0100' ).

  ENDMETHOD.

  METHOD subtract.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>subtract( iv_a = '0100' iv_b = '01' )
      exp = 'FF' ).

    " equal operands give zero, the empty xstring
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>subtract( iv_a = '1234' iv_b = '1234' )
      exp = '' ).

  ENDMETHOD.

  METHOD compare.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>compare( iv_a = '0100' iv_b = 'FF' )
      exp = 1 ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>compare( iv_a = 'FF' iv_b = '0100' )
      exp = -1 ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>compare( iv_a = '00FF' iv_b = 'FF' )
      exp = 0 ).

  ENDMETHOD.

  METHOD normalize_large_prefix.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_value TYPE xstring.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '00' ).
    lv_value = li_random->bytes( 4096 ) && '01'.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>compare( iv_a = lv_value iv_b = '01' )
      exp = 0 ).
    lv_value = li_random->bytes( 4096 ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>compare( iv_a = lv_value iv_b = lv_value )
      exp = 0 ).
  ENDMETHOD.

  METHOD multiply.

    DATA lv_zero TYPE xstring.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>multiply( iv_a = 'FF' iv_b = 'FF' )
      exp = 'FE01' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>multiply( iv_a = 'ABCDEF' iv_b = '123456' )
      exp = '0C379A59BA4A' ).

    " multiplying by zero gives zero
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>multiply( iv_a = 'ABCDEF' iv_b = lv_zero )
      exp = '' ).

  ENDMETHOD.

  METHOD modulo.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>modulo( iv_a = '0100' iv_m = '07' )
      exp = '04' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>modulo( iv_a = '1234' iv_m = '1234' )
      exp = '' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>modulo( iv_a = 'DEADBEEFCAFE' iv_m = '010001' )
      exp = 'EABC' ).

  ENDMETHOD.

  METHOD mod_pow.

    DATA lv_zero TYPE xstring.

    " 2^10 mod 1000 = 24
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '02' iv_exp = '0A' iv_m = '03E8' )
      exp = '18' ).

    " 3^5 mod 7 = 5
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '03' iv_exp = '05' iv_m = '07' )
      exp = '05' ).

    " Same-width Montgomery bases still require reduction when base >= m.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '08' iv_exp = '01' iv_m = '07' )
      exp = '01' ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '07' iv_exp = '01' iv_m = '07' )
      exp = '' ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = 'FE' iv_exp = '03' iv_m = 'FB' )
      exp = '1B' ).

    " Bits following the directly initialized leading one still square/multiply.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '02' iv_exp = '02' iv_m = '07' )
      exp = '04' ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '03' iv_exp = '03' iv_m = '07' )
      exp = '06' ).

    " x^0 = 1
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow( iv_base = '05' iv_exp = lv_zero iv_m = '07' )
      exp = '01' ).

  ENDMETHOD.

  METHOD mod_pow_medium.

    " 128-bit modulus, exponent 65537 (as used by RSA)
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow(
        iv_base = '123456789ABCDEF0FEDCBA9876543210'
        iv_exp  = '010001'
        iv_m    = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61' )
      exp = 'F8D7DF0DF2B38FD953387F64670C78D3' ).

    " Independent 256-bit square-and-multiply vector, exponent 65537.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_bigint=>mod_pow(
        iv_base = '0FEDCBA98765432100123456789ABCDEF112233445566778899AABBCCDDEEFF0'
        iv_exp  = '010001'
        iv_m    = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F' )
      exp = '5E0136EBF7A6389D2C5229390C28DB84BF6D3844EBEB793BC015D8533EEBE48C' ).

  ENDMETHOD.

ENDCLASS.
