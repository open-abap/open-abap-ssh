CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS to_xstring FOR TESTING RAISING cx_static_check.
    METHODS from_xstring FOR TESTING RAISING cx_static_check.
    METHODS from_xstring_drops_crlf FOR TESTING RAISING cx_static_check.
    METHODS name_list FOR TESTING RAISING cx_static_check.
    METHODS roundtrip_printable FOR TESTING RAISING cx_static_check.
    METHODS with_space FOR TESTING RAISING cx_static_check.
    METHODS cr_lf FOR TESTING RAISING cx_static_check.
    METHODS text_controls FOR TESTING RAISING cx_static_check.
    METHODS utf8_text FOR TESTING RAISING cx_static_check.
    METHODS large_text FOR TESTING RAISING cx_static_check.
    METHODS large_identifier FOR TESTING RAISING cx_static_check.
    METHODS large_filtered_text FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD text_controls.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring_text( '41090A0D42' )
      exp = |A\t\n\rB| ).
  ENDMETHOD.


  METHOD utf8_text.
    DATA lv_expected TYPE string.
    lv_expected = cl_abap_codepage=>convert_from( '41E29C9342' ).
* Preserve the UTF-8 check mark while filtering the embedded SOH control.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring_text( '41E29C930142' )
      exp = lv_expected ).
  ENDMETHOD.


  METHOD large_text.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_data TYPE xstring.
    DATA lv_expected TYPE string.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '41424344090A0D20' ).
    lv_data = li_random->bytes( 32768 ).
    lv_expected = cl_abap_codepage=>convert_from( lv_data ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring_text( lv_data )
      exp = lv_expected ).
  ENDMETHOD.

  METHOD large_identifier.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_data TYPE xstring.
    DATA lv_expected TYPE string.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '41424344' ).
    lv_data = li_random->bytes( 32768 ).
    lv_expected = cl_abap_codepage=>convert_from( lv_data ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( lv_data )
      exp = lv_expected ).
  ENDMETHOD.

  METHOD large_filtered_text.
* Alternating valid/control bytes create thousands of disjoint valid runs.
* Filtering must preserve them without a growing-prefix concatenation loop.
    DATA li_input TYPE REF TO zif_oassh_random.
    DATA li_expected TYPE REF TO zif_oassh_random.
    DATA lv_data TYPE xstring.
    DATA lv_expected_hex TYPE xstring.
    DATA lv_expected TYPE string.
    li_input = NEW zcl_oassh_random_fixed( iv_pattern = '4100' ).
    li_expected = NEW zcl_oassh_random_fixed( iv_pattern = '41' ).
    lv_data = li_input->bytes( 8192 ).
    lv_expected_hex = li_expected->bytes( 4096 ).
    lv_expected = cl_abap_codepage=>convert_from( lv_expected_hex ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring_text( lv_data )
      exp = lv_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( lv_data )
      exp = lv_expected ).
  ENDMETHOD.

  METHOD to_xstring.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      exp = '5353482D322E302D61626170' ).

  ENDMETHOD.

  METHOD from_xstring.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( '5353482D322E302D61626170' )
      exp = 'SSH-2.0-abap' ).

  ENDMETHOD.

  METHOD from_xstring_drops_crlf.

    " version string with trailing CR LF, control bytes are dropped
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( '5353482D322E302D616261700D0A' )
      exp = 'SSH-2.0-abap' ).

  ENDMETHOD.

  METHOD name_list.

    " zlib,none
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( '7A6C69622C6E6F6E65' )
      exp = 'zlib,none' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>to_xstring( 'zlib,none' )
      exp = '7A6C69622C6E6F6E65' ).

  ENDMETHOD.

  METHOD roundtrip_printable.

    " full printable ASCII range, incl. the tricky punctuation
    DATA lv_text TYPE string.
    lv_text = ` !"#$%&'()*+,-./0123456789:;<=>?@` &&
              `ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` &&
              ```abcdefghijklmnopqrstuvwxyz{|}~`.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( zcl_oassh_ascii=>to_xstring( lv_text ) )
      exp = lv_text ).

  ENDMETHOD.

  METHOD with_space.

    " spaces occur in the software version comment field, RFC 4253 4.2
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>to_xstring( 'a b' )
      exp = '612062' ).

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring( '612062' )
      exp = 'a b' ).

  ENDMETHOD.

  METHOD cr_lf.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>c_cr_lf
      exp = '0D0A' ).

  ENDMETHOD.

ENDCLASS.
