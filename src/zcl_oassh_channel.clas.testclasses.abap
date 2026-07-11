CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS full_session FOR TESTING.
ENDCLASS.

CLASS ltcl_test IMPLEMENTATION.
  METHOD full_session.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lv_payload TYPE xstring.
    lo_channel = NEW #( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->open( )
      exp = '5A0000000773657373696F6E000000000010000000008000' ).

    " server confirms local channel 0, assigns remote channel 7
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-open ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->exec( 'echo hi' )
      exp = '6200000007000000046578656301000000076563686F206869' ).

    lo_channel->receive( '6300000000' ).
    " stdout can arrive in multiple packets
    lo_channel->receive( '5E00000000000000026869' ).
    lo_channel->receive( '5E00000000000000010A' ).
    lo_channel->receive( '5F000000000000000100000003657272' ).
    " exit-status request, want-reply FALSE, status 23
    lo_channel->receive( '62000000000000000B657869742D7374617475730000000017' ).
    lo_channel->receive( '6000000000' ).
    lv_payload = lo_channel->receive( '6100000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_payload
      exp = '6100000007' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_stdout( )
      exp = '68690A' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_stderr( )
      exp = '657272' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_exit_status( )
      exp = 23 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-closed ).
  ENDMETHOD.
ENDCLASS.
