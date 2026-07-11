CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS wire_format FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_50=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_50=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_50=>gc_message_id.
    ls_expected-user_name = zcl_oassh_ascii=>to_xstring( 'bob' ).
    ls_expected-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_expected-method_name = zcl_oassh_ascii=>to_xstring( 'password' ).
    ls_expected-password = zcl_oassh_ascii=>to_xstring( 'secret' ).
    lo_stream = zcl_oassh_message_50=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_50=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD wire_format.
* byte-exact layout: 0x32, string "a", string "ssh-connection",
* string "password", boolean FALSE, string "pw"
    DATA ls_data TYPE zcl_oassh_message_50=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_data-message_id = zcl_oassh_message_50=>gc_message_id.
    ls_data-user_name = zcl_oassh_ascii=>to_xstring( 'a' ).
    ls_data-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_data-method_name = zcl_oassh_ascii=>to_xstring( 'password' ).
    ls_data-password = zcl_oassh_ascii=>to_xstring( 'pw' ).
    lo_stream = zcl_oassh_message_50=>serialize( ls_data ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = '3200000001610000000E7373682D636F6E6E656374696F6E0000000870617373776F726400000000027077' ).
  ENDMETHOD.
ENDCLASS.
