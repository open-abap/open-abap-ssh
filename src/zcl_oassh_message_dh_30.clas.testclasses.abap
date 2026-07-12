CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS wire FOR TESTING.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_dh_30=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_dh_30=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_dh_30=>gc_message_id.
    ls_expected-e = '80AABB'.
    lo_stream = zcl_oassh_message_dh_30=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_dh_30=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD wire.
    DATA ls_data TYPE zcl_oassh_message_dh_30=>ty_data.
    ls_data-message_id = zcl_oassh_message_dh_30=>gc_message_id.
    ls_data-e = '80'.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_message_dh_30=>serialize( ls_data )->get( )
      exp = '1E000000020080' ).
  ENDMETHOD.
ENDCLASS.
