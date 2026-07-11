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
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD text_controls.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_ascii=>from_xstring_text( '41090A0D42' )
      exp = |A\t\n\rB| ).
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
