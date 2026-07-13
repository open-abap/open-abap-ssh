CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh_channel DEFINITION LOCAL FRIENDS ltcl_test.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS full_session FOR TESTING RAISING cx_static_check.
    METHODS wrong_recipient FOR TESTING RAISING cx_static_check.
    METHODS channel_failure FOR TESTING RAISING cx_static_check.
    METHODS channel_open_failure FOR TESTING RAISING cx_static_check.
    METHODS replenishes_window FOR TESTING RAISING cx_static_check.
    METHODS server_requests FOR TESTING RAISING cx_static_check.
    METHODS lifecycle_rejected FOR TESTING RAISING cx_static_check.
    METHODS malformed_open_is_atomic FOR TESTING RAISING cx_static_check.
    METHODS malformed_running_is_atomic FOR TESTING RAISING cx_static_check.
    METHODS uint32_window FOR TESTING RAISING cx_static_check.
    METHODS utf8_command FOR TESTING RAISING cx_static_check.
    METHODS subsystem_request FOR TESTING RAISING cx_static_check.
    METHODS subsystem_failure FOR TESTING RAISING cx_static_check.
    METHODS drains_incrementally FOR TESTING RAISING cx_static_check.
    METHODS sends_data FOR TESTING RAISING cx_static_check.
    METHODS client_closes FOR TESTING RAISING cx_static_check.
    METHODS maximum_data_packets FOR TESTING RAISING cx_static_check.
    METHODS empty_data_not_retained FOR TESTING RAISING cx_static_check.
ENDCLASS.

CLASS ltcl_test IMPLEMENTATION.
  METHOD empty_data_not_retained.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    DO 4096 TIMES.
      lo_channel->receive( '5E0000000000000000' ).
      lo_channel->receive( '5F000000000000000100000000' ).
    ENDDO.
    cl_abap_unit_assert=>assert_initial( lo_channel->mt_stdout ).
    cl_abap_unit_assert=>assert_initial( lo_channel->mt_stderr ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->mv_local_window
      exp = 1048576 ).
  ENDMETHOD.


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
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->exec( 'false' ).
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


  METHOD maximum_data_packets.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_data TYPE xstring.
    DATA lv_reason TYPE i.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    lv_data = li_random->bytes( 32768 ).
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).

* Both message shapes accept the complete maximum advertised in CHANNEL_OPEN.
    lo_stream = NEW #( ).
    lo_stream->append( '5E' ).
    lo_stream->uint32_encode( 0 ).
    lo_stream->string_encode( lv_data ).
    lo_channel->receive( lo_stream->get( ) ).
    lo_stream = NEW #( ).
    lo_stream->append( '5F' ).
    lo_stream->uint32_encode( 0 ).
    lo_stream->uint32_encode( 1 ).
    lo_stream->string_encode( lv_data ).
    lo_channel->receive( lo_stream->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lo_channel->get_stdout( ) )
      exp = 32768 ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lo_channel->get_stderr( ) )
      exp = 32768 ).

* The larger transport envelope must not let ordinary data exceed that limit.
    lo_stream = NEW #( ).
    lo_stream->append( '5E' ).
    lo_stream->uint32_encode( 0 ).
    lo_stream->string_encode( li_random->bytes( 32769 ) ).
    TRY.
        lo_channel->receive( lo_stream->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).

    CLEAR lv_reason.
    lo_stream = NEW #( ).
    lo_stream->append( '5F' ).
    lo_stream->uint32_encode( 0 ).
    lo_stream->uint32_encode( 1 ).
    lo_stream->string_encode( li_random->bytes( 32769 ) ).
    TRY.
        lo_channel->receive( lo_stream->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.


  METHOD channel_open_failure.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    DATA lv_failure TYPE xstring VALUE
      '5C00000000000000010000000664656E69656400000000'.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    TRY.
        lo_channel->receive( lv_failure ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-channel_failed ).

* A refusal is only valid while an open request is outstanding.
    lo_channel = NEW #( ).
    CLEAR lv_reason.
    TRY.
        lo_channel->receive( lv_failure ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.


  METHOD server_requests.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lv_reply TYPE xstring.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->exec( 'true' ).
    lo_channel->receive( '6300000000' ).

* A recognized request with want-reply receives CHANNEL_SUCCESS.
    lv_reply = lo_channel->receive( '62000000000000000B657869742D7374617475730100000017' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_reply
      exp = '6300000007' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_exit_status( )
      exp = 23 ).

* Unknown request-specific bytes are ignored and want-reply receives failure.
    lv_reply = lo_channel->receive( '620000000000000003666F6F01AABB' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_reply
      exp = '6400000007' ).

* A control byte cannot be filtered out to create the exit-status token.
    lv_reply = lo_channel->receive( '62000000000000000C657869742D007374617475730100000063' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_reply
      exp = '6400000007' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_exit_status( )
      exp = 23 ).
  ENDMETHOD.


  METHOD lifecycle_rejected.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_channel = NEW #( ).

* Channel data is invalid before open confirmation.
    TRY.
        lo_channel->receive( '5E0000000000000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).

    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).

* A failure response is invalid when no channel request is outstanding.
    CLEAR lv_reason.
    TRY.
        lo_channel->receive( '6400000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).

* EOF is a one-way transition; duplicate EOF is invalid.
    lo_channel->receive( '6000000000' ).
    CLEAR lv_reason.
    TRY.
        lo_channel->receive( '6000000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.


  METHOD malformed_open_is_atomic.
* Reject the complete malformed message before committing its channel fields.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    TRY.
        lo_channel->receive( '5B00000000000000070020000000008000AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-open_sent ).

* The valid response remains usable after rejection; no partial state leaked.
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-open ).
  ENDMETHOD.


  METHOD malformed_running_is_atomic.
* Output, exit status, and lifecycle changes require an exact message shape.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->exec( 'true' ).
    lo_channel->receive( '6300000000' ).

    TRY.
        lo_channel->receive( '5E000000000000000178AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
    cl_abap_unit_assert=>assert_initial( lo_channel->get_stdout( ) ).

    CLEAR lv_reason.
    TRY.
        lo_channel->receive( '62000000000000000B657869742D7374617475730000000017AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_exit_status( )
      exp = -1 ).

    CLEAR lv_reason.
    TRY.
        lo_channel->receive( '6000000000AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-running ).

    CLEAR lv_reason.
    TRY.
        lo_channel->receive( '6100000000AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-running ).
  ENDMETHOD.


  METHOD uint32_window.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_channel = NEW #( ).
    lo_channel->open( ).
* Initial remote window 0xFFFFFFFE cannot be represented by signed ABAP i.
    lo_channel->receive( '5B0000000000000007FFFFFFFE00008000' ).
    lo_channel->receive( '5D0000000000000001' ).
    TRY.
* Increasing 0xFFFFFFFF again violates RFC 4254 section 5.2.
        lo_channel->receive( '5D0000000000000001' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.


  METHOD subsystem_request.
* RFC 4254 section 6.5: byte 98, recipient channel 7, "subsystem", want_reply
* TRUE, then the subsystem name "sftp". CHANNEL_SUCCESS advances to running.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->subsystem( 'sftp' )
      exp = '62000000070000000973756273797374656D010000000473667470' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-exec_sent ).
    lo_channel->receive( '6300000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-running ).
  ENDMETHOD.


  METHOD subsystem_failure.
* A server that lacks the subsystem answers CHANNEL_FAILURE; surface it typed.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->subsystem( 'sftp' ).
    TRY.
        lo_channel->receive( '6400000000' ).
        cl_abap_unit_assert=>fail( 'subsystem failure ignored' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-channel_failed ).
    ENDTRY.
  ENDMETHOD.


  METHOD drains_incrementally.
* An owner draining after each receive gets only the newly arrived bytes while
* the channel is still open, and nothing remains buffered afterwards.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->subsystem( 'sftp' ).
    lo_channel->receive( '6300000000' ).

    lo_channel->receive( '5E00000000000000026869' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->drain_stdout( )
      exp = '6869' ).

* A second drain with no new data returns nothing.
    cl_abap_unit_assert=>assert_initial( lo_channel->drain_stdout( ) ).

    lo_channel->receive( '5E00000000000000010A' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->drain_stdout( )
      exp = '0A' ).

* Drained bytes are not returned again by get_stdout( ) at close.
    cl_abap_unit_assert=>assert_initial( lo_channel->get_stdout( ) ).
  ENDMETHOD.


  METHOD sends_data.
* RFC 4254 section 5.2: exact DATA envelope and unsigned remote-window debit.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070000002000000010' ).
    lo_channel->subsystem( 'sftp' ).
    lo_channel->receive( '6300000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->data( '01020304' )
      exp = '5E000000070000000401020304' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->mv_remote_window
      exp = '0000001C' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_send_capacity( )
      exp = 16 ).
    TRY.
        lo_channel->data( '0000000000000000000000000000000000' ).
        cl_abap_unit_assert=>fail( 'remote maximum packet ignored' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-channel_failed ).
    ENDTRY.

* Exhaustion stalls at zero and WINDOW_ADJUST resumes up to max-packet credit.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070000000600000004' ).
    lo_channel->subsystem( 'sftp' ).
    lo_channel->receive( '6300000000' ).
    lo_channel->data( '01020304' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_send_capacity( )
      exp = 2 ).
    lo_channel->data( '0506' ).
    cl_abap_unit_assert=>assert_initial( lo_channel->get_send_capacity( ) ).
    lo_channel->receive( '5D0000000000000005' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_send_capacity( )
      exp = 4 ).
  ENDMETHOD.


  METHOD client_closes.
* A locally initiated CLOSE is not echoed when the mandatory peer CLOSE arrives.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_channel->subsystem( 'sftp' ).
    lo_channel->receive( '6300000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->close( )
      exp = '6100000007' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-close_sent ).
    cl_abap_unit_assert=>assert_initial( lo_channel->receive( '6100000000' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-closed ).
  ENDMETHOD.


  METHOD utf8_command.
    DATA lo_channel TYPE REF TO zcl_oassh_channel.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_payload TYPE xstring.
    DATA lv_command TYPE string.
    lo_channel = NEW #( ).
    lo_channel->open( ).
    lo_channel->receive( '5B00000000000000070020000000008000' ).
    lv_command = cl_abap_codepage=>convert_from( '6563686F20E29C93' ).
    lv_payload = lo_channel->exec( lv_command ).
    lo_stream = NEW #( lv_payload ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->take( 1 )
      exp = '62' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->uint32_decode( )
      exp = 7 ).
    lo_stream->string_decode( ).
    lo_stream->boolean_decode( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->string_decode( )
      exp = '6563686F20E29C93' ).
  ENDMETHOD.
ENDCLASS.
