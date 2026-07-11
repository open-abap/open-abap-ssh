CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_6=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_expected-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lo_stream = zcl_oassh_message_6=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_6=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.
ENDCLASS.
