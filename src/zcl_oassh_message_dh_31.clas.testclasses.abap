CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS wire FOR TESTING.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_dh_31=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_dh_31=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_dh_31=>gc_message_id.
    ls_expected-k_s = 'AABB'.
    ls_expected-f = '80CCDD'.
    ls_expected-signature = 'EEFF'.
    lo_stream = zcl_oassh_message_dh_31=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_dh_31=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD wire.
    DATA ls_data TYPE zcl_oassh_message_dh_31=>ty_data.
    ls_data-message_id = zcl_oassh_message_dh_31=>gc_message_id.
    ls_data-k_s = 'AA'.
    ls_data-f = '80'.
    ls_data-signature = 'BB'.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_message_dh_31=>serialize( ls_data )->get( )
      exp = '1F00000001AA00000002008000000001BB' ).
  ENDMETHOD.
ENDCLASS.
