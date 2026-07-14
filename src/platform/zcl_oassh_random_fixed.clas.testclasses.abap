CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS default_pattern FOR TESTING RAISING cx_static_check.
    METHODS custom_pattern FOR TESTING RAISING cx_static_check.
    METHODS cycles FOR TESTING RAISING cx_static_check.
    METHODS zero_length FOR TESTING RAISING cx_static_check.
    METHODS large FOR TESTING RAISING cx_static_check.
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

  METHOD large.

    " length not a multiple of the (3-byte) pattern, larger than the
    " doubling buffer's first step, and requested twice to exercise reuse
    DATA li_random  TYPE REF TO zif_oassh_random.
    DATA lv_actual  TYPE xstring.
    DATA lv_expected TYPE xstring.

    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '112233' ).

    lv_actual = li_random->bytes( 32768 ).

    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lv_actual )
      exp = 32768 ).

    " build the expected repeated pattern independently and compare in full
    WHILE xstrlen( lv_expected ) < 32768.
      lv_expected = lv_expected && '112233'.
    ENDWHILE.
    lv_expected = lv_expected(32768).

    cl_abap_unit_assert=>assert_equals(
      act = lv_actual
      exp = lv_expected ).

    " a second call returns the same result (buffer reuse)
    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 32768 )
      exp = lv_actual ).

    " a shorter follow-up call slices correctly from the grown buffer
    cl_abap_unit_assert=>assert_equals(
      act = li_random->bytes( 5 )
      exp = '1122331122' ).

  ENDMETHOD.

ENDCLASS.
