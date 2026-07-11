CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS wire FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_1=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_1=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_1=>gc_message_id.
    ls_expected-reason_code = zcl_oassh_message_1=>c_reason-by_application.
    ls_expected-description = zcl_oassh_ascii=>to_xstring( 'bye' ).
    ls_expected-language_tag = zcl_oassh_ascii=>to_xstring( 'en' ).
    lo_stream = zcl_oassh_message_1=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_1=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.

  METHOD wire.
* id 01, reason 0000000B (11), "bye" (3 bytes), "" (0 bytes)
    DATA ls_data TYPE zcl_oassh_message_1=>ty_data.
    ls_data-message_id = zcl_oassh_message_1=>gc_message_id.
    ls_data-reason_code = 11.
    ls_data-description = zcl_oassh_ascii=>to_xstring( 'bye' ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_message_1=>serialize( ls_data )->get( )
      exp = '010000000B0000000362796500000000' ).
  ENDMETHOD.
ENDCLASS.
