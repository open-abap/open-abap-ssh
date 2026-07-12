CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS add FOR TESTING RAISING cx_static_check.
    METHODS subtract FOR TESTING RAISING cx_static_check.
    METHODS compare FOR TESTING RAISING cx_static_check.
    METHODS multiply FOR TESTING RAISING cx_static_check.
    METHODS modulo FOR TESTING RAISING cx_static_check.
    METHODS mod_pow FOR TESTING RAISING cx_static_check.
    METHODS mod_pow_medium FOR TESTING RAISING cx_static_check.
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

  ENDMETHOD.

ENDCLASS.
