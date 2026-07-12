CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS add_wraps FOR TESTING RAISING cx_static_check.
    METHODS mul_and_inverse FOR TESTING RAISING cx_static_check.
    METHODS sub_borrows FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD roundtrip.
* a little-endian value below p survives from_le/to_le unchanged
    DATA lv_in TYPE xstring VALUE
      '0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_field25519=>to_le( zcl_oassh_field25519=>from_le( lv_in ) )
      exp = lv_in ).
  ENDMETHOD.


  METHOD add_wraps.
* (p-1) + 2 = 1 mod p. p-1 little-endian is p with the low byte one less.
    DATA lt_pm1 TYPE zcl_oassh_field25519=>ty_field.
    DATA lt_two TYPE zcl_oassh_field25519=>ty_field.
    DATA lt_sum TYPE zcl_oassh_field25519=>ty_field.
    lt_pm1 = zcl_oassh_field25519=>from_le( 'ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F' ).
    lt_two = zcl_oassh_field25519=>from_le( '0200000000000000000000000000000000000000000000000000000000000000' ).
    lt_sum = zcl_oassh_field25519=>add(
      it_a = lt_pm1
      it_b = lt_two ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_field25519=>to_le( lt_sum )
      exp = '0100000000000000000000000000000000000000000000000000000000000000' ).
  ENDMETHOD.


  METHOD mul_and_inverse.
* a * inv(a) = 1 for a non-trivial element
    DATA lt_a TYPE zcl_oassh_field25519=>ty_field.
    DATA lt_prod TYPE zcl_oassh_field25519=>ty_field.
    lt_a = zcl_oassh_field25519=>from_le( '0900000000000000000000000000000000000000000000000000000000000000' ).
    lt_prod = zcl_oassh_field25519=>mul(
      it_a = lt_a
      it_b = zcl_oassh_field25519=>inv( lt_a ) ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_field25519=>to_le( lt_prod )
      exp = '0100000000000000000000000000000000000000000000000000000000000000' ).
  ENDMETHOD.


  METHOD sub_borrows.
* 1 - 2 = p - 1 mod p
    DATA lt_one TYPE zcl_oassh_field25519=>ty_field.
    DATA lt_two TYPE zcl_oassh_field25519=>ty_field.
    lt_one = zcl_oassh_field25519=>one( ).
    lt_two = zcl_oassh_field25519=>from_le( '0200000000000000000000000000000000000000000000000000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_field25519=>to_le( zcl_oassh_field25519=>sub(
              it_a = lt_one
              it_b = lt_two ) )
      exp = 'ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F' ).
  ENDMETHOD.

ENDCLASS.
