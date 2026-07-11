CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    METHODS setup.
    METHODS name_list FOR TESTING RAISING cx_static_check.
    METHODS unit32 FOR TESTING RAISING cx_static_check.
    METHODS uint32_peek FOR TESTING RAISING cx_static_check.
    METHODS constructor FOR TESTING RAISING cx_static_check.
    METHODS append_take FOR TESTING RAISING cx_static_check.
    METHODS clear FOR TESTING RAISING cx_static_check.
    METHODS boolean_true FOR TESTING RAISING cx_static_check.
    METHODS boolean_false FOR TESTING RAISING cx_static_check.
    METHODS boolean_roundtrip FOR TESTING RAISING cx_static_check.
    METHODS byte FOR TESTING RAISING cx_static_check.
    METHODS string FOR TESTING RAISING cx_static_check.
    METHODS mpint_zero FOR TESTING RAISING cx_static_check.
    METHODS mpint_positive FOR TESTING RAISING cx_static_check.
    METHODS mpint_high_bit FOR TESTING RAISING cx_static_check.
    METHODS mpint_strip_leading FOR TESTING RAISING cx_static_check.
    METHODS mpint_decode_test FOR TESTING RAISING cx_static_check.
    METHODS mpint_roundtrip FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD setup.
    CREATE OBJECT mo_stream.
  ENDMETHOD.

  METHOD name_list.

    DATA lt_list TYPE string_table.
    APPEND 'zlib' TO lt_list.
    APPEND 'none' TO lt_list.

    mo_stream->name_list_encode( lt_list ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000097A6C69622C6E6F6E65' ).

    cl_abap_unit_assert=>assert_equals(
      act = lines( mo_stream->name_list_decode( ) )
      exp = 2 ).

  ENDMETHOD.

  METHOD unit32.

    DATA lv_int TYPE i VALUE 699921578.

    mo_stream->uint32_encode( lv_int ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '29B7F4AA' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode( )
      exp = 699921578 ).

  ENDMETHOD.

  METHOD uint32_peek.

    mo_stream->uint32_encode( 42 ).

    " peek does not consume
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode_peek( )
      exp = 42 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 4 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode( )
      exp = 42 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).

  ENDMETHOD.

  METHOD constructor.

    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    CREATE OBJECT lo_stream EXPORTING iv_hex = 'ABCDEF'.

    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = 'ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 3 ).

  ENDMETHOD.

  METHOD append_take.

    mo_stream->append( '0011' ).
    mo_stream->append( '2233' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 4 ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 2 )
      exp = '0011' ).

    " take consumes from the front
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '2233' ).

  ENDMETHOD.

  METHOD clear.

    mo_stream->append( '00112233' ).
    mo_stream->clear( ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).

  ENDMETHOD.

  METHOD boolean_true.

    mo_stream->boolean_encode( abap_true ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '01' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->boolean_decode( )
      exp = abap_true ).

  ENDMETHOD.

  METHOD boolean_false.

    mo_stream->boolean_encode( abap_false ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->boolean_decode( )
      exp = abap_false ).

  ENDMETHOD.

  METHOD boolean_roundtrip.

    " any non-zero byte decodes to TRUE
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    CREATE OBJECT lo_stream EXPORTING iv_hex = 'FF'.

    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->boolean_decode( )
      exp = abap_true ).

  ENDMETHOD.

  METHOD byte.

    mo_stream->byte_encode( 'AB' ).
    mo_stream->byte_encode( 'CD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = 'ABCD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->byte_decode( )
      exp = 'AB' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->byte_decode( )
      exp = 'CD' ).

  ENDMETHOD.

  METHOD string.

    DATA lv_payload TYPE xstring VALUE 'DEADBEEF'.
    mo_stream->string_encode( lv_payload ).

    " uint32 length prefix (4 bytes) + data
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00000004DEADBEEF' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->string_decode( )
      exp = 'DEADBEEF' ).

  ENDMETHOD.

  METHOD mpint_zero.
* RFC 4251: value 0 is stored as a string with zero bytes of data
    mo_stream->mpint_encode( `` ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00000000' ).

  ENDMETHOD.

  METHOD mpint_positive.
* RFC 4251 example: 9a378f9b2e332a7 -> 00 00 00 08 09 a3 78 f9 b2 e3 32 a7
    mo_stream->mpint_encode( '09A378F9B2E332A7' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '0000000809A378F9B2E332A7' ).

  ENDMETHOD.

  METHOD mpint_high_bit.
* RFC 4251 example: 80 -> 00 00 00 02 00 80 (zero byte prepended)
    mo_stream->mpint_encode( '80' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000020080' ).

  ENDMETHOD.

  METHOD mpint_strip_leading.
* unnecessary leading zero bytes must be removed before encoding
    mo_stream->mpint_encode( '00000080' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000020080' ).

  ENDMETHOD.

  METHOD mpint_decode_test.

    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    " high-bit value: sign byte is stripped on decode
    CREATE OBJECT lo_stream EXPORTING iv_hex = '000000020080'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '80' ).

    " plain positive value: returned unchanged
    CREATE OBJECT lo_stream EXPORTING iv_hex = '0000000809A378F9B2E332A7'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '09A378F9B2E332A7' ).

    " zero
    CREATE OBJECT lo_stream EXPORTING iv_hex = '00000000'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '' ).

  ENDMETHOD.

  METHOD mpint_roundtrip.

    DATA lv_value TYPE xstring VALUE '80'.
    mo_stream->mpint_encode( lv_value ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->mpint_decode( )
      exp = lv_value ).

  ENDMETHOD.

ENDCLASS.
