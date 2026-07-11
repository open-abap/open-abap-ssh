CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS default_pattern FOR TESTING RAISING cx_static_check.
    METHODS custom_pattern FOR TESTING RAISING cx_static_check.
    METHODS cycles FOR TESTING RAISING cx_static_check.
    METHODS zero_length FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD default_pattern.

    DATA li_random TYPE REF TO zif_oassh_random.
    li_random = NEW zcl_oassh_random_fixed( ).

    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 4 )
      exp = 'ABABABAB' ).

  ENDMETHOD.

  METHOD custom_pattern.

    DATA li_random TYPE REF TO zif_oassh_random.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '1122' ).

    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 4 )
      exp = '11221122' ).

  ENDMETHOD.

  METHOD cycles.

    " length not a multiple of the pattern wraps mid-pattern
    DATA li_random TYPE REF TO zif_oassh_random.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '1122' ).

    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 3 )
      exp = '112211' ).

  ENDMETHOD.

  METHOD zero_length.

    DATA li_random TYPE REF TO zif_oassh_random.
    li_random = NEW zcl_oassh_random_fixed( ).

    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 0 )
      exp = '' ).

  ENDMETHOD.

ENDCLASS.
