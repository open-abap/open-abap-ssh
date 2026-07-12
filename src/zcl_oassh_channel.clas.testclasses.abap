CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS full_session FOR TESTING RAISING cx_static_check.
    METHODS wrong_recipient FOR TESTING RAISING cx_static_check.
    METHODS channel_failure FOR TESTING RAISING cx_static_check.
    METHODS replenishes_window FOR TESTING RAISING cx_static_check.
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


  METHOD wrong_recipient.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_channel = NEW #( ).
    TRY.
        lo_channel->receive( '5E0000000100000000' ).
        cl_abap_unit_assert=>fail( 'foreign channel data accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-malformed_packet ).
    ENDTRY.
  ENDMETHOD.


  METHOD channel_failure.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_channel = NEW #( ).
    TRY.
        lo_channel->receive( '6400000000' ).
        cl_abap_unit_assert=>fail( 'channel failure ignored' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-channel_failed ).
    ENDTRY.
  ENDMETHOD.


  METHOD replenishes_window.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_chunk TYPE xstring.
    DATA lv_message TYPE xstring.
    DATA lv_reply TYPE xstring.
    DATA lv_expected TYPE xstring.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    lv_chunk = li_random->bytes( 32768 ).
    lo_stream = NEW #( ).
    lo_stream->append( '5E' ).
    lo_stream->uint32_encode( 0 ).
    lo_stream->string_encode( lv_chunk ).
    lv_message = lo_stream->get( ).

* Sixteen maximum-sized chunks consume exactly half the advertised MiB.
    DO 16 TIMES.
      lv_reply = lo_channel->receive( lv_message ).
      IF sy-index < 16.
        cl_abap_unit_assert=>assert_initial( lv_reply ).
      ENDIF.
    ENDDO.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reply
      exp = '5D0000000700080000' ).
    lv_expected = li_random->bytes( 524288 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_stdout( )
      exp = lv_expected ).
  ENDMETHOD.
ENDCLASS.
