CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh DEFINITION LOCAL FRIENDS ltcl_test.

CLASS lcl_host_verifier DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
ENDCLASS.

CLASS lcl_host_verifier IMPLEMENTATION.
  METHOD zif_oassh_host_verifier~verify.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS connect_sends_version FOR TESTING RAISING cx_static_check.
    METHODS close_clears_secrets FOR TESTING RAISING cx_static_check.
    METHODS server_version_starts_kex FOR TESTING RAISING cx_static_check.
    METHODS identification_validation FOR TESTING RAISING cx_static_check.
    METHODS fragmented_kex_header FOR TESTING RAISING cx_static_check.
    METHODS execute_returns_result FOR TESTING RAISING cx_static_check.
    METHODS shell_returns_raw FOR TESTING RAISING cx_static_check.
    METHODS global_request FOR TESTING RAISING cx_static_check.
    METHODS server_channel_open FOR TESTING RAISING cx_static_check.
    METHODS transport_messages FOR TESTING RAISING cx_static_check.
    METHODS disconnect_stops_processing FOR TESTING RAISING cx_static_check.
    METHODS encrypted_message_recognition FOR TESTING RAISING cx_static_check.
    METHODS plain_unknown_unimplemented FOR TESTING RAISING cx_static_check.
    METHODS execute_timeout FOR TESTING RAISING cx_static_check.
    METHODS exec_stream_session FOR TESTING RAISING cx_static_check.
    METHODS exec_stream_guards FOR TESTING RAISING cx_static_check.
    METHODS sftp_session_dispatch FOR TESTING RAISING cx_static_check.
    METHODS sftp_session_guards FOR TESTING RAISING cx_static_check.
    METHODS workflow_interfaces FOR TESTING RAISING cx_static_check.
    METHODS sftp_api_state FOR TESTING RAISING cx_static_check.
    METHODS empty_command_state FOR TESTING RAISING cx_static_check.
    METHODS execute_early_failure FOR TESTING RAISING cx_static_check.
    METHODS utf8_credentials FOR TESTING RAISING cx_static_check.
    METHODS recorded_session FOR TESTING RAISING cx_static_check.
    METHODS shell_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_upload_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_stat_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_list_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_mutation_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_session_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_mutation_recorded_in_a
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_mutation_recorded_in_b
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_mutation_recorded_out
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS shell_recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS shell_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_upload_recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_upload_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_stat_recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_stat_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_list_recorded_in_a
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_list_recorded_in_b
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_list_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_open
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_list
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_download
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_stat
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_rename1
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_rename2
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_close
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS session_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS build_ssh RETURNING VALUE(ro_ssh) TYPE REF TO zcl_oassh.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD workflow_interfaces.
    DATA li_exec TYPE REF TO zif_oassh_interactive_exec.
    DATA li_one_shot TYPE REF TO zif_oassh_sftp_one_shot.
    DATA li_session TYPE REF TO zif_oassh_sftp_session.
    DATA lx_error TYPE REF TO zcx_oassh_error.

    li_exec = build_ssh( ).
    TRY.
        li_exec->exec_open(
          iv_command         = 'true'
          iv_timeout_seconds = 0 ).
        cl_abap_unit_assert=>fail( 'interactive interface did not delegate' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '001' ).
    ENDTRY.

    li_one_shot = build_ssh( ).
    TRY.
        li_one_shot->sftp_download(
          iv_path            = '/tmp/file'
          iv_timeout_seconds = 0 ).
        cl_abap_unit_assert=>fail( 'one-shot interface did not delegate' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '001' ).
    ENDTRY.

    li_session = build_ssh( ).
    TRY.
        li_session->sftp_open( 0 ).
        cl_abap_unit_assert=>fail( 'session interface did not delegate' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '001' ).
    ENDTRY.
  ENDMETHOD.

  METHOD close_clears_secrets.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    lo_ssh = build_ssh( ).
    lo_ssh->mv_private_seed = '0102'.
    lo_ssh->mo_transport->mv_password = '0304'.
    lo_ssh->mo_transport->mv_private_seed = '0506'.
    cl_abap_unit_assert=>assert_not_initial( lo_ssh->mv_password ).

    lo_ssh->close( ).

    cl_abap_unit_assert=>assert_initial( lo_ssh->mv_password ).
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_password_supplied ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->mv_private_seed ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->mo_transport->mv_password ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->mo_transport->mv_private_seed ).
  ENDMETHOD.

  METHOD encrypted_message_recognition.
    cl_abap_unit_assert=>assert_true( zcl_oassh=>is_recognized_message( 53 ) ).
    cl_abap_unit_assert=>assert_true( zcl_oassh=>is_recognized_message( 80 ) ).
    cl_abap_unit_assert=>assert_true( zcl_oassh=>is_recognized_message( 90 ) ).
    cl_abap_unit_assert=>assert_false( zcl_oassh=>is_recognized_message( 83 ) ).
    cl_abap_unit_assert=>assert_false( zcl_oassh=>is_recognized_message( 200 ) ).
  ENDMETHOD.


  METHOD plain_unknown_unimplemented.
* Non-strict KEX must ignore unknown packets after replying with sequence zero.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lo_server_packet TYPE REF TO zcl_oassh_packet.
    DATA lo_client_packet TYPE REF TO zcl_oassh_packet.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_wire TYPE xstring.
    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    lo_server_packet = NEW #( li_random ).
    lo_client_packet = NEW #( li_random ).
    li_socket->connect( ).
    lv_wire = lo_server_packet->encode( 'C8' ).
    lo_ssh->mo_stream->append( lv_wire ).

    lo_ssh->process_kex( ).

    cl_abap_unit_assert=>assert_equals(
      act = lo_client_packet->decode( lo_mock->get_sent( ) )
      exp = '0300000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_true( lo_mock->is_connected( ) ).
  ENDMETHOD.

  METHOD build_ssh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    ro_ssh = NEW #(
      ii_socket        = NEW zcl_oassh_socket_mock( )
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
  ENDMETHOD.

  METHOD transport_messages.
* RFC 4253 section 11 control messages are handled centrally and consumed
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.

    " IGNORE (02): string "x"
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '020000000178' ) ).

    " DEBUG (04): always_display=false, "hi", ""
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '040000000002686900000000' ) ).

    " UNIMPLEMENTED (03): sequence number 7
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '0300000007' ) ).

    " DISCONNECT (01): reason 11 (by_application), "gone", ""
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true(
      lo_ssh->handle_transport_message( '010000000B00000004676F6E6500000000' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_disconnect_reason( )
      exp = zcl_oassh_message_1=>c_reason-by_application ).

    " a non-control message is not consumed
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_false( lo_ssh->handle_transport_message( '5E00000000' ) ).

    " recognized control messages must not hide trailing bytes
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->handle_transport_message( '010000000B00000004676F6E650000000000' ).
        cl_abap_unit_assert=>fail( 'trailing transport data accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_disconnected ).
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_operation_done ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->get_disconnect_reason( ) ).
  ENDMETHOD.

  METHOD global_request.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    lo_mock = NEW #( ).
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = lo_mock
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->process_global_request( '5000000004686F73740100000003616263' )
      exp = '52' ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->process_global_request( '5000000004686F737400' ) ).
  ENDMETHOD.

  METHOD execute_returns_result.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_output TYPE string.
    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->mo_channel = NEW #( ).
    lo_ssh->mo_channel->open( ).
    lo_ssh->mo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_ssh->mo_channel->exec( 'echo hi' ).
    lo_ssh->mo_channel->receive( '6300000000' ).
    lo_ssh->mo_channel->receive( '5E000000000000000368690A' ).
    lo_ssh->mo_channel->receive( '5F000000000000000100000003657272' ).
    lo_ssh->mo_channel->receive( '62000000000000000B657869742D7374617475730000000000' ).
    lo_ssh->mo_channel->receive( '6100000000' ).
    lo_ssh->mv_operation_done = abap_true.
    lv_output = lo_ssh->execute( 'echo hi' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = |hi\n| ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_stderr( )
      exp = 'err' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_exit_status( )
      exp = 0 ).
    lo_ssh->close( ).
    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
  ENDMETHOD.


  METHOD execute_timeout.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->execute(
          iv_command         = 'echo hi'
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).

    lo_ssh = build_ssh( ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute(
          iv_command         = 'echo hi'
          iv_timeout_seconds = 0 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).
  ENDMETHOD.


  METHOD exec_stream_session.
* Drive the channel directly like execute_returns_result: the interactive
* exec surface is exercised without a transport handshake. The open
* confirmation advertises a zero remote window so queued stdin is retained
* instead of requiring an encrypted send.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_data TYPE xstring.
    DATA lv_reason TYPE symsgno.
    lo_ssh = build_ssh( ).
    lo_ssh->mv_operation_started = abap_true.
    lo_ssh->mv_operation = zcl_oassh=>gc_operation-exec_stream.
    lo_ssh->mo_channel = NEW #( ).
    lo_ssh->mo_channel->open( ).
    lo_ssh->mo_channel->receive( '5B00000000000000070000000000008000' ).
    lo_ssh->mo_channel->exec( 'git-upload-pack repo' ).
    lo_ssh->mo_channel->receive( '6300000000' ).

    " stdin queues while the remote window is exhausted
    lo_ssh->exec_write( 'AABB' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_exec_outbound
      exp = 'AABB' ).

    " a half-close would drop the queued stdin, so it is rejected
    TRY.
        lo_ssh->exec_eof( ).
        cl_abap_unit_assert=>fail( 'EOF with queued stdin accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).

    " buffered CHANNEL_DATA is returned without a socket read
    lo_ssh->mo_channel->receive( '5E000000000000000368690A' ).
    lv_data = lo_ssh->exec_read( ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_data
      exp = '68690A' ).
    cl_abap_unit_assert=>assert_false( lo_ssh->exec_is_closed( ) ).

    " CHANNEL_EOF ends the stream: empty read result plus exec_is_closed
    lo_ssh->mo_channel->receive( '6000000000' ).
    cl_abap_unit_assert=>assert_true( lo_ssh->exec_is_closed( ) ).
    lv_data = lo_ssh->exec_read( ).
    cl_abap_unit_assert=>assert_initial( lv_data ).

    " the peer's CLOSE completes the operation without another exchange
    lo_ssh->mo_channel->receive( '6100000000' ).
    lo_ssh->exec_close( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-closed ).
    cl_abap_unit_assert=>assert_true( lo_ssh->exec_is_closed( ) ).
  ENDMETHOD.


  METHOD exec_stream_guards.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.

    " read and write require an interactive exec operation
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->exec_read( ).
        cl_abap_unit_assert=>fail( 'exec_read without exec_open accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->exec_write( 'AA' ).
        cl_abap_unit_assert=>fail( 'exec_write without exec_open accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).

    " exec_open without server bytes is a timeout
    CLEAR lv_reason.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->exec_open(
          iv_command         = 'true'
          iv_timeout_seconds = 1 ).
        cl_abap_unit_assert=>fail( 'exec_open without server accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).

    " one operation per connection, as for all other operations
    CLEAR lv_reason.
    TRY.
        lo_ssh->exec_open( 'true' ).
        cl_abap_unit_assert=>fail( 'second operation accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).
  ENDMETHOD.


  METHOD server_channel_open.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->reject_channel_open(
        '5A0000000773657373696F6E000000070020000000008000' )
      exp = '5C00000007000000010000000000000000' ).

* The common fields are mandatory even though type-specific data is ignored.
    TRY.
        lo_ssh->reject_channel_open( '5A0000000773657373696F6E00000007' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
  ENDMETHOD.

  METHOD disconnect_stops_processing.
* RFC 4253 section 11.1: buffered data after DISCONNECT must not be accepted
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_disconnect_wire TYPE xstring.
    DATA lv_trailing_wire TYPE xstring.
    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    lo_packet = NEW #( li_random ).
    lv_disconnect_wire = lo_packet->encode( '010000000B00000004676F6E6500000000' ).
    lv_trailing_wire = lo_packet->encode( '0200000000' ).
    li_socket->connect( ).
    lo_ssh->mo_stream->append( lv_disconnect_wire ).
    lo_ssh->mo_stream->append( lv_trailing_wire ).

    lo_ssh->process_kex( ).

    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_disconnect_reason( )
      exp = zcl_oassh_message_1=>c_reason-by_application ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = xstrlen( lv_trailing_wire ) ).
* Bytes already buffered by the adapter must also be rejected after close.
    lo_ssh->process_inbound( 'AA' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = xstrlen( lv_trailing_wire ) ).
  ENDMETHOD.


  METHOD empty_command_state.
* RFC 4254 section 6.5 encodes the command as an unrestricted SSH string.
* Its empty value must not be confused with "execute was never called".
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->execute(
          iv_command         = ''
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).
    cl_abap_unit_assert=>assert_true( lo_ssh->mv_operation_started ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->mv_command ).

* A second call must still be rejected even though the first command text was
* empty. This API owns a single session channel and is intentionally one-shot.
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute( 'second' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).
  ENDMETHOD.


  METHOD execute_early_failure.
* A transport close or error before authentication/channel establishment is
* terminal when no SSH channel was completed.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_mock = NEW #( ).
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = lo_mock
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    lo_mock->set_closed( ).
    TRY.
        lo_ssh->execute( 'echo hi' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).
  ENDMETHOD.


  METHOD utf8_credentials.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_user TYPE string.
    DATA lv_password TYPE string.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lv_user = cl_abap_codepage=>convert_from( '4AC3B67267' ).
    lv_password = cl_abap_codepage=>convert_from( '70C3A47373' ).
    lo_ssh = NEW #(
      ii_socket        = NEW zcl_oassh_socket_mock( )
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = lv_user
      iv_password      = lv_password ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_user
      exp = '4AC3B67267' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_password
      exp = '70C3A47373' ).
  ENDMETHOD.


  METHOD recorded_session.
* Captured from the pinned OpenSSH 10.3 CI container with fixed AB randomness.
* This drives the real client from version exchange through encrypted exec.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_output TYPE string.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lo_mock->set_replay( recorded_inbound( ) ).

    lv_output = lo_ssh->execute( 'printf open-abap-ssh' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = 'open-abap-ssh' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_exit_status( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_true( lo_ssh->mo_transport->is_strict_kex( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = recorded_outbound( ) ).
    lo_ssh->close( ).
    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
  ENDMETHOD.


  METHOD shell_recorded_session.
* Fixed-AB replay of the complete pinned OpenSSH PTY + shell transaction.
* Both encrypted streams are exact, including stdin DATA and client EOF.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_output TYPE xstring.
    DATA lv_expected TYPE xstring.
    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lo_mock->set_replay( shell_recorded_inbound( ) ).

    lv_output = lo_ssh->shell( '7072696E7466206F70656E2D616261702D7373682D7368656C6C0A657869740A' ).

    lv_expected = lv_expected &&
      '57656C636F6D6520746F204F70656E535348205365727665720D0A1B5B3F32303034686363363664'.
    lv_expected = lv_expected &&
      '313836386334653A7E24207072696E7466206F70656E2D616261702D7373682D7368656C6C0D0A'.
    lv_expected = lv_expected &&
      '1B5B3F323030346C0D6F70656E2D616261702D7373682D7368656C6C1B5B3F3230303468636336'.
    lv_expected = lv_expected &&
      '3664313836386334653A7E2420657869740D0A1B5B3F323030346C0D6C6F676F75740D0A'.
    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = lv_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_exit_status( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = shell_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD shell_returns_raw.
* Terminal output is intentionally binary-safe: control sequences and bytes
* that are not valid UTF-8 must not pass through the execute text filter.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lv_output TYPE xstring.
    lo_ssh = build_ssh( ).
    lo_ssh->mo_channel = NEW #( ).
    lo_ssh->mo_channel->open( ).
    lo_ssh->mo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_ssh->mo_channel->pty(
      iv_terminal = 'xterm'
      iv_columns  = 80
      iv_rows     = 24 ).
    lo_ssh->mo_channel->receive( '6300000000' ).
    lo_ssh->mo_channel->shell( ).
    lo_ssh->mo_channel->receive( '6300000000' ).
    lo_ssh->mo_channel->receive( '5E00000000000000041B5B6DFF' ).
    lo_ssh->mo_channel->receive( '6100000000' ).
    lo_ssh->mv_operation_done = abap_true.

    lv_output = lo_ssh->shell( '657869740A' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = '1B5B6DFF' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_operation
      exp = zcl_oassh=>gc_operation-shell ).
  ENDMETHOD.


  METHOD sftp_session_dispatch.
* Drive the channel directly like exec_stream_session: the session surface is
* exercised without a transport handshake. The open confirmation advertises a
* zero remote window so the queued SFTP output is retained rather than
* requiring an encrypted send. This checks the advance_channel session case:
* subsystem-running bring-up (INIT) and VERSION handling, plus sftp_close.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    lo_ssh = build_ssh( ).
    lo_ssh->mv_operation_started = abap_true.
    lo_ssh->mv_operation = zcl_oassh=>gc_operation-sftp_session.
    lo_ssh->mo_sftp = NEW #( ).
    lo_ssh->mo_channel = NEW #( ).
    lo_ssh->mo_channel->open( ).
    lo_ssh->mo_channel->receive( '5B00000000000000070000000000008000' ).
    lo_ssh->mo_channel->subsystem( 'sftp' ).

    " CHANNEL_SUCCESS moves the channel to running and triggers the INIT
    " bring-up; the zero window keeps it queued instead of sending it.
    lo_ssh->advance_channel( '6300000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-version_pending ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_sftp_outbound
      exp = '000000050100000003' ).

    " CHANNEL_DATA carrying VERSION completes the handshake: session ready,
    " no operation dispatched (mo_sftp has no selected operation yet).
    lo_ssh->advance_channel( '5E0000000000000009000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-ready ).

    " sftp_close over an already-closed channel completes without a send.
    lo_ssh->mv_sftp_session = abap_true.
    lo_ssh->mo_channel->close( ).
    lo_ssh->mo_channel->receive( '6100000000' ).
    lo_ssh->sftp_close( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_channel->get_state( )
      exp = zcl_oassh_channel=>c_state-closed ).
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_sftp_session ).
  ENDMETHOD.


  METHOD sftp_session_guards.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.

    " sftp_open is one operation per connection like every other kind
    lo_ssh = build_ssh( ).
    lo_ssh->mv_operation_started = abap_true.
    TRY.
        lo_ssh->sftp_open( ).
        cl_abap_unit_assert=>fail( 'sftp_open after another operation accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).

    " a non-positive timeout is rejected before any channel work
    CLEAR lv_reason.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->sftp_open( 0 ).
        cl_abap_unit_assert=>fail( 'sftp_open with zero timeout accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).

    " sftp_close without an open session is invalid
    CLEAR lv_reason.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->sftp_close( ).
        cl_abap_unit_assert=>fail( 'sftp_close without a session accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).

    " a broken session refuses further operations but not close
    CLEAR lv_reason.
    lo_ssh = build_ssh( ).
    lo_ssh->mv_sftp_session = abap_true.
    lo_ssh->mv_sftp_session_broken = abap_true.
    TRY.
        lo_ssh->sftp_list( '/tmp' ).
        cl_abap_unit_assert=>fail( 'operation on a broken session accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).

    " a non-positive timeout on an in-session operation is a timeout error
    CLEAR lv_reason.
    lo_ssh = build_ssh( ).
    lo_ssh->mv_sftp_session = abap_true.
    lo_ssh->mo_sftp = NEW #( ).
    TRY.
        lo_ssh->sftp_stat(
          iv_path            = '/tmp'
          iv_timeout_seconds = 0 ).
        cl_abap_unit_assert=>fail( 'in-session operation with zero timeout accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).
  ENDMETHOD.


  METHOD sftp_api_state.
* SFTP shares the one-operation contract and validates timeout before channel
* setup, while retaining binary output as xstring at the API boundary.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->sftp_download(
          iv_path            = '/missing'
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '001' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_operation
      exp = zcl_oassh=>gc_operation-sftp_download ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute( 'second operation' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '010' ).
  ENDMETHOD.


  METHOD sftp_list_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* Replay covers NAME parsing, the repeated READDIR, EOF, and handle CLOSE.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_inbound_a TYPE xstring.
    DATA lv_inbound_b TYPE xstring.
    DATA lv_inbound TYPE xstring.
    DATA lt_names TYPE zcl_oassh_sftp=>ty_names.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lv_inbound_a = sftp_list_recorded_in_a( ).
    lv_inbound_b = sftp_list_recorded_in_b( ).
    CONCATENATE lv_inbound_a lv_inbound_b INTO lv_inbound IN BYTE MODE.
    lo_mock->set_replay( lv_inbound ).

    lt_names = lo_ssh->sftp_list( '/config/oassh-list' ).

    cl_abap_unit_assert=>assert_equals(
      act = lines( lt_names )
      exp = 4 ).
    READ TABLE lt_names WITH KEY filename = '612E62696E' TRANSPORTING NO FIELDS.
    cl_abap_unit_assert=>assert_subrc( ).
    READ TABLE lt_names WITH KEY filename = '622E747874' TRANSPORTING NO FIELDS.
    cl_abap_unit_assert=>assert_subrc( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = sftp_list_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD sftp_stat_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* The full stream and returned raw uint64 size are deterministic.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA ls_attrs TYPE zcl_oassh_sftp=>ty_attrs.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lo_mock->set_replay( sftp_stat_recorded_inbound( ) ).

    ls_attrs = lo_ssh->sftp_stat( '/config/sftp-fixture.bin' ).

    cl_abap_unit_assert=>assert_true( ls_attrs-has_size ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-size
      exp = '0000000000000010' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = sftp_stat_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD sftp_upload_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* Verify complete inbound consumption and exact encrypted upload output.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_data TYPE xstring.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lo_mock->set_replay( sftp_upload_recorded_inbound( ) ).
    lv_data = '010203'.

    lo_ssh->sftp_upload(
      iv_path = '/config/sftp-upload.bin'
      iv_data = lv_data ).

    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = sftp_upload_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD sftp_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* The complete inbound stream is consumed and every outbound byte must match.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_data TYPE xstring.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lo_mock->set_replay( sftp_recorded_inbound( ) ).

    lv_data = lo_ssh->sftp_download( '/config/sftp-fixture.bin' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_data
      exp = '6F70656E2D616261702D7366747000FF' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = sftp_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.

  METHOD connect_sends_version.

    DATA lo_mock   TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh    TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.

    lo_mock = NEW zcl_oassh_socket_mock( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).

    CREATE OBJECT lo_ssh
      EXPORTING
        ii_socket        = li_socket
        ii_random        = li_random
        ii_host_verifier = li_verifier
        iv_host          = 'test.example'
        iv_port          = '22'
        iv_user          = 'test'
        iv_password      = 'test'.

    li_socket->connect( ).
    lo_ssh->send_version( ).

    " the client version string, SSH-2.0-abap followed by CR LF
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = '5353482D322E302D616261700D0A' ).

  ENDMETHOD.


  METHOD server_version_starts_kex.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lo_decoder TYPE REF TO zcl_oassh_packet.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_kexinit TYPE zcl_oassh_message_20=>ty_data.
    DATA lv_sent TYPE xstring.
    DATA lv_wire TYPE xstring.
    DATA lv_version TYPE xstring.
    DATA lv_client_length TYPE i.
    DATA lv_trailing TYPE xstring VALUE 'AABB'.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lv_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ).
    lv_version = '6C6567616C207365727665722062616E6E65720D0A' &&
      lv_version && zcl_oassh_ascii=>c_cr_lf.
    CONCATENATE lv_version lv_trailing INTO lv_version IN BYTE MODE.
    lo_ssh->process_inbound( lv_version ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get( )
      exp = 'AABB' ).

    lv_sent = lo_mock->get_sent( ).
    lv_client_length = xstrlen( zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ) ) + 2.
    lv_wire = lv_sent+lv_client_length.
    lo_decoder = NEW #( ii_random = li_random ).
    lo_stream = NEW #( lo_decoder->decode( lv_wire ) ).
    ls_kexinit = zcl_oassh_message_20=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_kexinit-cookie
      exp = 'ABABABABABABABABABABABABABABABAB' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_kexinit-kex_algorithms[ 1 ]
      exp = 'curve25519-sha256' ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists( ls_kexinit-kex_algorithms[ table_line = 'kex-strict-c' ] ) ) ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists(
        ls_kexinit-kex_algorithms[ table_line = 'kex-strict-c-v00@openssh.com' ] ) ) ).
  ENDMETHOD.


  METHOD identification_validation.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    DATA lv_line TYPE xstring.
    DATA lt_malformed TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.

* RFC 4253 section 4.2: 253 bytes plus CR LF is the maximum accepted line.
    lo_ssh = build_ssh( ).
    lo_ssh->mi_socket->connect( ).
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '41' ).
    lv_line = '5353482D322E302D' &&
      li_random->bytes( 245 ) &&
      zcl_oassh_ascii=>c_cr_lf.
    lo_ssh->mo_stream->append( lv_line ).
    lo_ssh->process_version( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_state
      exp = zcl_oassh=>gc_state-key_exchange ).

* A malformed SSH-prefixed line is rejected with a typed protocol error.
    lo_ssh = build_ssh( ).
    lo_ssh->mo_stream->append( '5353482D392E302D6261640D0A' ).
    TRY.
        lo_ssh->process_version( ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).

* 254 bytes before CR LF exceeds the 255-byte inclusive maximum.
    lo_ssh = build_ssh( ).
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '41' ).
    lv_line = '5353482D322E302D' &&
      li_random->bytes( 246 ) &&
      zcl_oassh_ascii=>c_cr_lf.
    lo_ssh->mo_stream->append( lv_line ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->process_version( ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).

* Empty, whitespace-containing, hyphenated software tokens and NUL bytes are
* forbidden by the identification grammar.
    APPEND '5353482D322E302D' TO lt_malformed.
    APPEND '5353482D322E302D20636F6D6D656E74' TO lt_malformed.
    APPEND '5353482D322E302D6261642D6E616D65' TO lt_malformed.
    APPEND '5353482D322E302D676F6F642062616400' TO lt_malformed.
    LOOP AT lt_malformed INTO lv_line.
      CLEAR lv_reason.
      TRY.
          zcl_oassh=>validate_server_identification( lv_line ).
        CATCH zcx_oassh_error INTO lx_error.
          lv_reason = lx_error->if_t100_message~t100key-msgno.
      ENDTRY.
      cl_abap_unit_assert=>assert_equals(
        act = lv_reason
        exp = '003' ).
    ENDLOOP.

* An unterminated diagnostic line is bounded even when fragmented.
    lo_ssh = build_ssh( ).
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '41' ).
    lo_ssh->mo_stream->append( li_random->bytes( 35000 ) ).
    lo_ssh->process_version( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->mv_version_prefix_checked ).
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_version_is_ssh ).
    lo_ssh->mo_stream->append( '41' ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->process_version( ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '002' ).

* New fragments continue from the previous byte rather than rescanning.
    lo_ssh = build_ssh( ).
    lo_ssh->mo_stream->append( '41' ).
    lo_ssh->process_version( ).
    lo_ssh->mo_stream->append( '42' ).
    lo_ssh->process_version( ).
    lo_ssh->mo_stream->append( '43' ).
    lo_ssh->process_version( ).
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_version_prefix_checked ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 3 ).
  ENDMETHOD.


  METHOD fragmented_kex_header.
* Once the plaintext packet length is available, later one-byte callbacks
* must reuse it instead of peeking/materializing the growing packet again.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    lo_ssh = build_ssh( ).
    lo_ssh->mo_stream->append( '0000800000000000' ).
    lo_ssh->process_kex( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_plain_packet_length
      exp = 32768 ).
    DO 4096 TIMES.
      lo_ssh->mo_stream->append( 'AA' ).
      lo_ssh->process_kex( ).
      cl_abap_unit_assert=>assert_equals(
        act = lo_ssh->mv_plain_packet_length
        exp = 32768 ).
    ENDDO.
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 4104 ).
  ENDMETHOD.


  METHOD recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914D9FE0D9AE68F00AA9CA4F79F'.
    rv_data = rv_data && '17FD1278000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '727361000000030100010000018100E32C8FF7D9CE54FC0AE1C961A06E8AB5609103B31E8B95EDAE'.
    rv_data = rv_data && '59BFEB5163FB7E8C014BF993D4320B36DC7180FA4FECEC752CBC8852673802A05B3A5ABEC276F69F'.
    rv_data = rv_data && '98648D0788D1AFDD046CDE52AA753738B38E9EC8EEE2979348766C851E93AB886E38F74E69416657'.
    rv_data = rv_data && '7323FE5966D5F9BDCF4EA2541005EC40548AE8A6D794AB7F1119B1644AEF4ED3A763B8F9CF9BED6B'.
    rv_data = rv_data && 'C289A25714499BC745EFD369C9333E79DB9E271FD0DA2C2549B3426C1144E417BF0F12314D8FE27C'.
    rv_data = rv_data && 'A26156062E8C9068B051EF2F84028D09675698ABC7FE4C29C69D5B4D645354A628422CD4517693A3'.
    rv_data = rv_data && 'E4C432D6534DA4BAB183F3ADA765899E4D4B69BBC0E496D1838AF1B51641D20CDD5DCC09F42BACF5'.
    rv_data = rv_data && 'FFE285CCECB1F9EB9990D66980264652F25F1E2364448D0D189430D824D09BBA30E75DFA6CBC3F8F'.
    rv_data = rv_data && '659C2F87F58B38211209AA3AC7E41390D32BBFA0EC142EC19C61C907A36E281C5CE8B60AB9EFB486'.
    rv_data = rv_data && '765E948B852BA31A39DCA0A18A254EEABC0B86E76F011F267C92FFD31452DBFB13CAFB1CE106D300'.
    rv_data = rv_data && '000020E90920BFB1D196D76DCF72A143841B48CD9233A34126DDA098488BA2DCFDC47A0000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001809E7E9F29DD939F3EE84C89AFC6A1B551700D07FCA6'.
    rv_data = rv_data && '11CAA2F06E9A1E5D4F533A7D09AA17B418C56C2E031612ACF34FF7026E5C8E61CD55879186C39190'.
    rv_data = rv_data && '0FB60E0907E9B5CBB88740D4E7B933182438CD1558D66FA628147637356D77F30A6733F9B9256408'.
    rv_data = rv_data && 'E25EB226D27D2294C4C9830E81E8FB496E9EF851E19216E208549444CDDF44E531E86BAB8588E435'.
    rv_data = rv_data && '711733BEAF5A03F4ACDD144DFC999408679923C8E58C663F137A955F1C18CDE6C4923262DF62F752'.
    rv_data = rv_data && 'D156A278F2F732EC0254B5AB93E195F3DBB50018C3A6FDB7F31543BE0098480D1ED0930BCB4FDB1F'.
    rv_data = rv_data && '911CCD7139860A3B22FFC94572CF017B137E1B44B395027EC11713F935B45354768F838CFF5D1F14'.
    rv_data = rv_data && '5328B8D1991BEF256C8545E7BB2ABC9C8FA4EF27012F9B9FBB56C425E5132B3834BFC2012B2EA7AF'.
    rv_data = rv_data && '801A9276B01CB6F7A99EF8E7BE2F72FAC8152B2314A54715290D44314EB66442BBCC31A3717184DA'.
    rv_data = rv_data && '22518C3937AECB74DC5FF3B36200A2A0B7E22925865C802ED7D8C627F38990DB2AA1400C5D5BE75D'.
    rv_data = rv_data && 'DCB9B400000000000000000000000000000C0A150000000000000000000061D6D10E904029E0659E'.
    rv_data = rv_data && '2D38F35D7413A8524740D4A717E414F0053D9DB9BE08AFE8340763B7FC82EC187970ABC41F798C71'.
    rv_data = rv_data && 'CF4F6675A4D1D5F2978CB79639AFAF9099373783C762F5BB172F787299C15B893A3BB23910A94B20'.
    rv_data = rv_data && 'E5CA0216D18C5E4A145CC591546047D54F97D1A6EB8338AFB995D6C8CF5D8D98211C7C8FDE6DA911'.
    rv_data = rv_data && '7FC06D3DA424737AD717A6FD0D2C68E11EFFF27FDCB6753E0747377F62A04A66A05F7CCE718DF243'.
    rv_data = rv_data && '56CB037AE976403124F4B8F6CD30B582FDFC5A5813960CA7155A6BCCE2F951133182886394260E28'.
    rv_data = rv_data && 'BDA022FC08E96DE53144143534C99737F3CEB4D96874CEC95BFE4799822E24A66FC6689839ECFFBD'.
    rv_data = rv_data && '51CA6CC16F0FD83A942EBA2A03F22E0661C12DAF169418F9B876EE18924C3CBFC7ECE7857DAD042E'.
    rv_data = rv_data && '7690FF95E7D71438DD5C9F29A5EEA58D2E4C7B957D5E3ED88B58F48F4ACB9DE940A9C9CAFC77B213'.
    rv_data = rv_data && '7964BB476C9676657E2D0C8D7FE1629A420E647C6F4336ACC3EA6BC9FF9212F3B4F4F75EF47009FE'.
    rv_data = rv_data && 'F2917133ECC427BCF113B392532F6ADB49F0B73FB77FDCEF7848D1D7EE00251723A4F363E96E111F'.
    rv_data = rv_data && 'F71B4E7A5479792DAA23F497CAD53D7FCBF4111E09E0204EB3FBCB72B8819043C78945B0018AABE5'.
    rv_data = rv_data && '3EFFFEEE460BF160FA681A15A111C3F46ADD1679E81FAE2B75929F21704173E51F61B5D67AA9049B'.
    rv_data = rv_data && 'EEF4A80039DB8B2FD76C7D3A05E32D4E5CD7469BAA5BAB22A91543E60D45AA0E6C538251C243D417'.
    rv_data = rv_data && '865C0D72905A9EC02D6009B13C7BF6CCE4BCA1927E0CA9AEF5EEAE8A93861D3C151E271DFD1C6F83'.
    rv_data = rv_data && '829E0B795C3C7CD37A81134576843E5D9F3D39E34E61CDB0CA95CF21468CD28E33FBC775CADE9757'.
    rv_data = rv_data && '38E1618F83BADF046406B2621A544E00AE1460E87B7C223A34F529AB4C7AC9AB337013900E128597'.
    rv_data = rv_data && '1F09B066D3EC32932040E29D2AEC2ED854BE4D09D2F049ECEB42907B1D28618D770E106A166A7153'.
    rv_data = rv_data && 'E211CDAED05A90A7EA9F2EE6B448F37A96F68DA7001081F21BC8D243E9B374E4CD20633BC3E62ECB'.
    rv_data = rv_data && 'B3F6B5C833D5E4B05F5C6E5DC2853C57BF197680D0A18AA7315205E01DB666E9D2C8E7563BE48512'.
    rv_data = rv_data && '14E66BE687A3CA86C44A18173CAF3089538A765E54AF8A0AF51041E800F4ECD80B19E529391C6BBC'.
    rv_data = rv_data && '56B52949B4CE4FC6250141C6671341C80A20F29B9A2EE295845C2E8C06A9D56430DBE9014FC552EC'.
    rv_data = rv_data && '2F448872F2EB5A1E172D07BFE93EC991365884A7103A2904F81ECE711AA863C8D60E6BB7DF903D63'.
    rv_data = rv_data && '7B5783BD0E44DCBEA2590E6E6181D71BC4B7D6DA921233D741B783BBC93D53D1C6DF53A48549F0B6'.
    rv_data = rv_data && '60886BAA19BC7C32D9C3DFFC86E3B62FC4DE22D835C0E9C7D5D71009F3D31EE2F99D3E739CE8055C'.
    rv_data = rv_data && 'E5993961C4AA605C7C69C243FC7D074C7A19DD3E5CFFCAC76BA33AA8D4910CD3FAA4CEBA2156774C'.
    rv_data = rv_data && 'E1475C219A433948978DABB1DDCE7DEFB476141F737F33206C6BF1F70F53F8E42CB31E2D7C6CF2E0'.
    rv_data = rv_data && '05289FD18FA356FA7461BEA64A48E3D9C2D742515C2FDDE7FF1D3B2B1128B7F4B6EAE47DB9F4D31A'.
    rv_data = rv_data && 'D1E95685C041A5A6E2176DC0E1208E3F9294BBC2DC3994638B70122AB6601EF70E8AA0ABFBA79850'.
    rv_data = rv_data && 'CF5C4E6B5F98FBB33ED4949B9627CBCEDA41D445AD7583C003E7B928DDC11CB0E9AA6E87613A3F5A'.
    rv_data = rv_data && 'C748A3AF851073A7722C57C9201C'.
  ENDMETHOD.


  METHOD recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABABF9F071B034B1FD869E4916A77A187EA24490'.
    rv_data = rv_data && '09026D444A2CCA4824289ED1EED1CDE3227073F6EF6C8E8EEF21B36B401E176C89E0993FC64CA6E5'.
    rv_data = rv_data && 'C6F012F14D61245E5FD0C0781CDFF7ADAC266D7E5E46B096A2711650AE620AFEA294925440B8E48F'.
    rv_data = rv_data && '5062DF545627C2E6CA8AE3DC835870D59C8D0A314DCFA230C34BC1E6246B347AE5656B933A824B08'.
    rv_data = rv_data && 'B732401977AFA911AC00A1F4341002DBB5F32723B7A5440D4ECF93E36EEB1513B419295F919C3ABD'.
    rv_data = rv_data && '37E6DF9D716ADAC30512BBEB17F1C11916F68662D15463B104012B76738D882E6F99FFC7C01456EC'.
    rv_data = rv_data && '71D89419FA7C3CF90B53DDB090293BADE895DA3E2E086EA5D50EAD1DF835FF7F45E140D0A4AEB022'.
    rv_data = rv_data && 'B4DCBE2BA4836C6C076A9C67B846690D8D2B67539C865EED36F9348DF7FD7FE76EC5F67ED8D501CB'.
    rv_data = rv_data && 'C52D2EE3B299FA53F4D3137654111000C289CE5272DC9022DA006C43C793E39019C20AD291E486F4'.
    rv_data = rv_data && '7F21CCF78F1740A103BB9842BBB37600C7DD4E2654DCC052193CAF5CE466'.
  ENDMETHOD.


  METHOD sftp_recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914BEE6FE6B54B2A4FE8218703A'.
    rv_data = rv_data && 'B08E4B3F000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '727361000000030100010000018100D33F31C7626237D027E9647EE290793297E0A61C6164245DEE'.
    rv_data = rv_data && 'DCD089787D72A40E49B51B808C895EBFAD96B32CB8D56C18D44EF19583CA810BB5BD956C290F0BCA'.
    rv_data = rv_data && '710AE3B7D7828DDB5D9DB057D6094AF24FC0C38B7A7708E676A350177E8073C23CB4E65832E3FC93'.
    rv_data = rv_data && '3038D09835D782BE2BEC56C4A9160809437B1BD892633F4FC76E7689A86017E446B02D8EF2C4A691'.
    rv_data = rv_data && 'CEF2C25DD93334EDCCA56A1C5FC739CDF6B7C38F72D16288AA8D06B906798D42950371AD27120568'.
    rv_data = rv_data && 'A99AC5BBB105D612286A110A1437E744A64E4314449EC1BD9EF9E325B590CDEFDDE24A3AA3D9EEDA'.
    rv_data = rv_data && '1B2A2944E92ADA0F3C08C6E3BCAB29365BA34C9C04ABA0790BF3B027100008D30B1503D591E945AF'.
    rv_data = rv_data && '27B7A5115BD8351B4D14B5EA36C750554B9BBF7F39998615F938DB319ACFB5F8D9FE9C87C35888E8'.
    rv_data = rv_data && 'EF865DF8287693D0FABA90B7A2A83A4CA212C6E4F6EFA5EC42643B3DD9A6AF95E5280F99F7A3FA10'.
    rv_data = rv_data && 'FF2379B9911148D85502EC0D9E98B0B40B67EC3685B356ACCD101885A09910D12FD5A091D922C700'.
    rv_data = rv_data && '00002023930FD4BC4BB43045A03AB4F8170027FE3CF32ACDD5CC86218B8D5D746B38130000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001800F200C25E248E59F8E72B55B4C57C37F5D5891F70D'.
    rv_data = rv_data && '6DBA3FCECE1C2187498C27B3801EB3E4BC0B3E0F8EFA1B3FB24A57D29802527ED21A1515ABAD7E72'.
    rv_data = rv_data && '87F1858BECE80AAA3E79D95CADDD08D9AFE61E4B7606F33A65A5F71E4332FB28323C39DB7ED1260D'.
    rv_data = rv_data && '5A79F306ABE8D6367F97A47A8B315FB13C2DEF211A7746BF893825E847D6FF5672417DBBB0D6DA05'.
    rv_data = rv_data && '0B69AB1E9F6F220C722B89B4D1F73688606F8BF4D18FEA9ACBF545F7C120B3B5187FB698974723C6'.
    rv_data = rv_data && 'B2CE9E87E9E1D98A3BB9702574079B682DF72BC8A00A2193FB5F8C2C7E69BB0ED50EF6FA1F6DDCFA'.
    rv_data = rv_data && 'E0CCFC12305BA6E7707F691DF9BB58A05D34FC00C43C649153D17CF9CC31CD3CC558B2339B76B5ED'.
    rv_data = rv_data && '4EA43B48FF8CA5D38FCAED9356E788F2AD1A60C2708477D9BB3AF3FEE191EBEC4DB676D3BADA973D'.
    rv_data = rv_data && 'DF0B31A443D5BBBA6F7EFC4D0490015A5AEBC55C73114751A59835F58EDF992B4704AC4E5DE7C3E5'.
    rv_data = rv_data && '213B5A1F6CEF5687C2582A70E69CE2953F2E05B726380534338BBB87BF4254AE9081DFB219D0FAFA'.
    rv_data = rv_data && '3A999200000000000000000000000000000C0A15000000000000000000007F39BE18E3260545672A'.
    rv_data = rv_data && 'CDE088D546923B0C9D4F1DCD25D4AB750929413D295068F351A10C8F1AC7E4E2B7DF8F8629126895'.
    rv_data = rv_data && '2372F35A0EBF1D3118108691245C1F4DB0269D6CA3253EF4D568ADB4C5B62F40E6FCEB994F3A8DDA'.
    rv_data = rv_data && '7F8C6ECBE8052D73AB854F4A967007227B604FA817C7EAA94E79A64CE312E127414432239116FDC7'.
    rv_data = rv_data && '8E4C57818AF939CA370ED0B99BB76B428B2F831A67752F3650CC04A92026CA1A53CCBF3419AB8253'.
    rv_data = rv_data && '4D315ECD49C2B6B42AE9B0045C04A1E56A6C3DAC97C5C83E94E55A8566555D2894AEAB3FF35686A7'.
    rv_data = rv_data && '525D09510B3B4E0C5F292E2B28A7624C5943BF8BAF9118DDB9F0C93F65126AF373F6551FEE16B929'.
    rv_data = rv_data && '6DC9D37A07BA11AFC94C875169954F6ABB15AEAA45464F704905ACDF150396062F49F50F837B2885'.
    rv_data = rv_data && '4EB15E92069EE91A02EC094E6F66FFB0CD41957939D7CF8326076800F6EA8619A177EC042ED41E78'.
    rv_data = rv_data && 'C966E3C74B93BABF6FE08D330F8A0A6E848CB4A257D210CF59F679B19F2BF5E9F7BDBE6EDD5CC3C5'.
    rv_data = rv_data && '88C419EDB61F5D8D74712E91052A4C83AA41A8923E7C71FBB21B61A73B19DE22BB2F52232B7AD0F0'.
    rv_data = rv_data && '24030C01F82C8242C0468B7A7BD46C5F8F0BACDEEC7E00F196CBF96529C5EB1FF284586A6FFFFEF4'.
    rv_data = rv_data && '47CAC4FF54E0D7C5B549B1FD0B2EC33628C3BFF541F26C49A353F22B7972CDDCCCB5CF003EDAE810'.
    rv_data = rv_data && 'BA079AB4028FA9DD138B1403C6CF535056B7CF9566F658FBC2094301487BF1FA283F163ADCDF5032'.
    rv_data = rv_data && '77D68C285500273ABF054F424EBF09874FDAF2D48F3D6487ADB89A3EBBDABBCD94843C42C536BC41'.
    rv_data = rv_data && 'E1B9534A9698507AB3E8E1A4CB332F8F8115295D7CD61A73847914DB0CB085098052CBDC5B4FE123'.
    rv_data = rv_data && 'B55CCD9F1F5BE1BEA4F01FFE89A9B6A0505FC69C3B31A3887461E42E757F44F6C4DC5576E17B6151'.
    rv_data = rv_data && 'D811269889C848337A5C50EB3CFFC4724E914291E584373E4A4971E3C6C8B71CD4C9F4D44F148427'.
    rv_data = rv_data && 'AD1756271D4A0D95920069199F4A997F71D8F766B455921A3FFC44845CE0716D596AE5F30E383DC7'.
    rv_data = rv_data && '86241A108F37261119ED732138AC523847A320780B222F1E5F6E2F5F5891274B8514114DE0C7507A'.
    rv_data = rv_data && '9F499797097E983C4FA1C22BE620D2FFA6C4A58FA78D2AA30E5804BD1986689B9D4A3174CFB36CEC'.
    rv_data = rv_data && '41627C787EFF16048E9AE112BE2C25076C186723C7EDF94EE75664B50CB098FD513533E7902A463F'.
    rv_data = rv_data && 'FEDBA2236DC013CCDD6A502027B34D6CE17AFDA9C690BC4049F73B5CE6FD89B5E3480F5B6D8AF392'.
    rv_data = rv_data && 'CFE88A705757A4A7930419AEBF82DC3E1A5BEF054032BF55CA62D7660EA9E3D6D0FE54AB52409D3B'.
    rv_data = rv_data && 'F52D103516BA3CF45BE5C8C30F816C49C6D4D849D73285FC97A0B047724E59CFF023B5231D244378'.
    rv_data = rv_data && '0DB553B38A000043AF967CCDFBA7E5C824345F127114B93D231ACDE2EDEAAE3D481283BD1B9C8DDA'.
    rv_data = rv_data && '040D4800AE2E8EF1CC82D0236F64FC9A941EEE9F45BCE379CF19FAA35BB2F9CF834B488EEF68340A'.
    rv_data = rv_data && '4782D822DD5CA91167B515F47E9FB6D8A6AE72168BC1C629568D1AE2F70D7960EF2EBD685AAE87D6'.
    rv_data = rv_data && '5D70C7DAA3BD54941F5451425873051F9AB59AE24BED3971F871D071E32FDDD6692F56CFB74DE7F7'.
    rv_data = rv_data && '16D674A9BBCE860FA6B54C246E38F413717E9C0CF7F3E3278804558AD72D62788F3F0474BBB1C6C6'.
    rv_data = rv_data && '552E67403BC10198E6FAEDD6A1602330FFCDDD1B6BB5C8C3D5B5FF3D40FD6686CD87706FBFDC1ACE'.
    rv_data = rv_data && '02163CD05DE8BC21B585F93FC385069ED68C75E7911E301BD41488FC7C58407B6382ED60424ADD83'.
    rv_data = rv_data && '3AA30BC956181ACB82A2B1A2B71AF3EE80535541F7965E127E565C1ED14F081E53F6046D15B43EA6'.
    rv_data = rv_data && '10285C6CD50C33C39F855DBB1034706A8B0D94A55AEBB49A3FF3DDE3AC41125664C6FD3A7F6A2856'.
    rv_data = rv_data && '49019710F29E3239D78364D09CFC284EF58DEBFE041554FBE9BE2C4ABCABA0D6B2C6C17F10E8ADC4'.
    rv_data = rv_data && '72BE7297194924769544246B3303ED2E94F1A07F999FA268D8E87E04A010074E6C42602ABA41475C'.
    rv_data = rv_data && '33E5DFC5A4D2223C7DB13B04C6513678E85F340BA98B1CF3891B980A0048BD28C7EC61B6F3CA7874'.
    rv_data = rv_data && '24538A1B68F8FE4E68F09FF03E001DEE77C5BB23FCF7EB27389ACA6FDE2CD941D2EDD1B88A2D9865'.
    rv_data = rv_data && 'FEC7229471C5C6BEB8662D037D45E04BCC872297189A027E207A4D11A115109388E7293647ACD3D2'.
    rv_data = rv_data && 'E77AB6E8A17C86DD0658D6C4429B5B7E380E028AA22AC6FC6D93ACA8915520823EC748569D202B5C'.
    rv_data = rv_data && '3279CEEA8C2E0492C0066FFED550E5EF888C020ED70AA4878C500BB690D7AD1AB7D5FEF967896A07'.
    rv_data = rv_data && 'C8BBE13E13DDB83E25C6560D2B6866D0DFF93CE73BEAD235E85B63735957E69645F770B4B7FA787C'.
    rv_data = rv_data && '811E70EC028D722556F712FEBB772A3DB2CE6ABAECCDC56D0E64AFD88BD73AF9A48D5A92273723E3'.
    rv_data = rv_data && 'CCF25F16763252E6B71A3D717163956AECA77E12A0FB9484356F928A71FC1E6D22D8A262386F5E8E'.
    rv_data = rv_data && 'C9C020C1EEA6AC8E2E171AA2A890B38AA51DF7872A3096BFED3DB2DEECE93C51117069BBDA06F98F'.
    rv_data = rv_data && '3E30D3BFA182D6FCB3AB5366FD52B9A934BAC8F85618'.
  ENDMETHOD.


  METHOD sftp_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABABE257DB0F13D3132E6E85BB941589CBE8D78B'.
    rv_data = rv_data && '3F24C7F2A4B80C935E7E625ED417B7085BACEF391EE98E28BF8EFB52984112F89DEFB51425C6DDF4'.
    rv_data = rv_data && '4E1C9B242D4C94FC112F9BC0A9792F2F3FA9D280F1AB8491ACC221D07991FBD79B3BBED0AAE297A6'.
    rv_data = rv_data && 'F1DAA25B843305D001AC202E1D8251B2B43CDE3D89EF4B65955FBEE1B345203E6AEDBD804B47D3A0'.
    rv_data = rv_data && '2AE50FC742E9D56E7E8CF660F1EC7280FBBE91A41BB3671A9F9176E6FB5C30743CA2BA9F520F22DE'.
    rv_data = rv_data && '1E8C8B94AB59CD8E63EF77FAAC1BA2743C874D268BC46B783F166CEEB0624DE321A38BD3F5D65512'.
    rv_data = rv_data && 'D5A73CFA4001421A0004796CB1B8881C22CD4285574A7EF66091A12A5E1C8A8F1BC8F4217EDBE386'.
    rv_data = rv_data && '8565207C811AFF2D7BFAF0439B7C11326E5D87E3036015E212808CE9B7FAEDC569E74BFA28A711B1'.
    rv_data = rv_data && 'ECBFF37A01C52749049A7E5B66E0EBE53146F4A1D14B8B61E9F302EA6A0A9924F342DA3DC2BAC25C'.
    rv_data = rv_data && 'A6F6A92D572CABC256CFC63BE1ECC8B6AF124D43A33A91EB7D2A47440E49FE9235251F6641003021'.
    rv_data = rv_data && '47496DABC41211FE4A20F69193786EBF89AAD3CB69B599AD37672887589D251D960264EB33C2DEFF'.
    rv_data = rv_data && '0916556B793B2361A763415087C2547752CF67DB2C7C847BE4BC190629397452A80128C1A14D92D1'.
    rv_data = rv_data && '6FB482642FBC77849497D386CA9D122D7F41750272728A15847A4B817981F62529FC3D9181EF4357'.
    rv_data = rv_data && '7BAFFD6DD1B0DB5FCC1C79923F3CACF146938FECE5961FB28B8F399B4FBB704BC68862A5BD173B2A'.
    rv_data = rv_data && 'D5C92ECDB397437437CE48E9E63191A75F608383D1E0D4675E01290A8C42AA87951232B0EDC1B1E6'.
    rv_data = rv_data && '71806D88C095040C8348FC835F70F59699E79F25CA43AF3793F9C93F42E5BAFE6F89FE4F89D3A03F'.
    rv_data = rv_data && '294FF2ADDFB95FFF90A78FF8122B13E721273372087070B2F5AD29BEEE0223E240662D862B279496'.
    rv_data = rv_data && '6EF626E5184265BF0A652EB5555D5650311E6C288E9AD3B9DA9E908EBDE678C4B1E79F0849B64B63'.
    rv_data = rv_data && '4090CDDAAA23E599C7E25896F50389CE69E511449B50E57FC06303FB046834B3AF8CDA1E0561A63B'.
    rv_data = rv_data && '85B6ED8E1411ED83D2E068D9716355FFC0A7E880115859C19CC445C74B1E'.
  ENDMETHOD.

  METHOD sftp_upload_recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914BE69842AD34AC5FAB9DF7A62'.
    rv_data = rv_data && '58AB44CF000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '727361000000030100010000018100E291E949F535C4C5C1D86B5E9C28677A798B371759FB2CFB59'.
    rv_data = rv_data && '32DC2B1CB9AAFBF19891C14B2BCC315BBC82B470404DDD910ED725345024DECE1CB1AA5D80EA59C7'.
    rv_data = rv_data && 'AB04443FFA505B80DE588940BDC0B184AEE58924A3FE5320F19CD7BFAA26E08853CF943D0DB92073'.
    rv_data = rv_data && 'CBC64F7FFE0403BA918BB298222A1B715EC16688B1AC8F323D7615BCA037AACF5C815D3E6AFA66C4'.
    rv_data = rv_data && 'D62C89E0450645300361D9FE9EEBE19D98E93518744F1E02D13E7510BECADA4D5F1715A8F4F53DC4'.
    rv_data = rv_data && 'C5A2CB068C256B1892FD548A9CA37DF000400B3EB9CBE5EBD118396CC1E628F84D2AB73719727B5A'.
    rv_data = rv_data && '6F706480E2D550DA0F061C01A7DC1995F4A662B2C64C4F2553C8638419C31FF3609CFDE6D61C87C4'.
    rv_data = rv_data && 'F027C206D14F998D88CAAA70B2DD2AAD6D7B45A7430630D3ADAF4C88A36BD03D8446113B7323CE2C'.
    rv_data = rv_data && '31784073090D7A4EBF5639C980E82E9DD54039159D623FAA20B3C45416A6609B2E98C86B8E214335'.
    rv_data = rv_data && '1CA89AC66BE40D4BBB536A99AE8419C8C0052ED9AF2CC03B4BC3C11E39E441A2FDA9AA402EB08700'.
    rv_data = rv_data && '00002048744B81FB01CD08DAC84ACD58BBCC84D361D950927AF27E22D17E50CB3F671F0000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001806E0663DC28E76FB7513AEE41DDCC7BB1E85BF932A6'.
    rv_data = rv_data && '1E0A795F5924C823AB39E440279176F16CCE8B7D0575312DE58FD534029F69E493D503229740592A'.
    rv_data = rv_data && 'B2C1204908A44FD4BC0248601907661C40ED9F4FCEBBB15329C0A53881648540F7CC95E811BCF69B'.
    rv_data = rv_data && '8AF13722809ADF4BE51570858B26615AF55ED4EEB886EC66DD40B7531599848880F4FE0FA33D40B0'.
    rv_data = rv_data && '3B429E974921B42509343F331DD86E1B6059855412C5873424765EE78DAF842C91998D7F6EC12ACB'.
    rv_data = rv_data && 'FA2127F6BFDF5AC5649939A992636FDAF11BFB9D83A5846504F84F3D3B70316822CF620FE22D752F'.
    rv_data = rv_data && 'B2BD486E8BCE823C3480D1754DDC447DEE9462A4CA8E69249E24E7970055F80F555A6E1F678B23F5'.
    rv_data = rv_data && 'ADDE306035968386DA0FA8E7934BBD30CD40681FF3CDB97E00C741AA6AEB7AFA99D575C09F53F075'.
    rv_data = rv_data && 'F27E937D77480A31C2F3224BF2111CB375BCAB526D5CB13520DBF862B3ABE15DA906A81B102A6899'.
    rv_data = rv_data && '08C846AC45375594173C7DFB91CCAA646613EEB894C1F97CDE65688B201ED3B9B24315FF0439C39C'.
    rv_data = rv_data && '69F35200000000000000000000000000000C0A15000000000000000000008BF34E49C420DD8849B9'.
    rv_data = rv_data && '8368FE406BCE2B35DA216D37BF11AEA3850CD26D31FF479F175619253EC675934E6C5EA5D167C207'.
    rv_data = rv_data && '39CF19F831861CDB3B91ED9278459DC08602338F72B43A64F303B741175759B839CA620B942B4390'.
    rv_data = rv_data && '9D0D9A755FC8FCFE75937FD5C40086DF4B65A150E2D67381D9EDDD29F791B8D6E54FD82664AF8F0A'.
    rv_data = rv_data && '3557F98EC43256B7A8581F238647970E96D246B01E8028081379728263BCE7A83C86D46644A4703A'.
    rv_data = rv_data && 'B2D2B9804B501E2035B826BD71EE53565DB6C170850C7DBB05BC94AEC226D0864EB87D05A3022400'.
    rv_data = rv_data && 'B01CDF69FD53490B0A58A8F524DA8BBB8E865D4C14BB5B117FFDD8B3EFEE449D7E1D07616D70E537'.
    rv_data = rv_data && '2C28F9167271072824F4DE61BD1BDE5AADE23434B44B60EEB887CB34475DB09EDD62289C41067309'.
    rv_data = rv_data && '712DC6045AA46E6EB58D3D37B4046F6704649805270F143EDAC510696ADDD541898087438055EFC9'.
    rv_data = rv_data && 'FAABE73DD89C4ED73D4E97EC5EDC8C3FA30B6657163EE6024183E73BDBD49D160FB1DDD9FA5E3557'.
    rv_data = rv_data && '4CD08F03729565F04236289B5D092561251648C995796DB442C2648C8E6960CD0CD825E483A0D84E'.
    rv_data = rv_data && '9AB62A54D1A084B53D7DFFB15795BBC0FE1295E1DC257BCEF621B1A9E93A62DF33C0A3583D5A9FC7'.
    rv_data = rv_data && '7BCD3683C86725F044D75FF3EC72915418DAC76EB7FE66EF1796EFD00D0770415D5ADAAA778AC4F0'.
    rv_data = rv_data && 'CFE0B58713FA7F066C0668E8D70C6A2F1AF5F023BC4F2A2CE96A56D85E7F64C33FB653D959D021DC'.
    rv_data = rv_data && 'A8D80FE12EEB4FA5C43567FE0D4C373AE1036D02F80390226C3546156B66FF71D5E878002A3C078F'.
    rv_data = rv_data && 'F9A5A4E9EA03137658AC1950306F9514D658FF9BD8DB971EE7255462971E9A801AC53D40A12493CD'.
    rv_data = rv_data && '6BBB9F940BB7B87B233F11C3034B49ED602FE15E867791DD5A91739C543381E3C60D19BA1231675F'.
    rv_data = rv_data && '3F8F025A0D0D417DAB76F780ED692A43E122805721359EF197D20697A85718F8547CEC18BA2F3D92'.
    rv_data = rv_data && '74C185500160C1EA719016E62647DBCB2EC6DC623330A48AF45B849D0AA8D0D0ECD38B360EB1B0BE'.
    rv_data = rv_data && 'BEFF89BFFBE0AB716B1816814BAB740294A89488E7FAA6CCF8153B018C7073F3E9C51811C0FB6205'.
    rv_data = rv_data && '45B7891957A6C3D25002CC5F7FB7BEA77980A433F39BD8519D7CF1742660668D0A2A69933CD41C27'.
    rv_data = rv_data && '38CCBCFC5A9AD269BF06B861D59E14BD4C83BFA19A76CA369F0E8CDC541D0D30F8032D822124FC68'.
    rv_data = rv_data && '773BE230C21CAA6D237314629156C3BA6B6F7C527367775B3DEFB70A62E3A5208005BA6B6FBEB092'.
    rv_data = rv_data && 'FC3B910CEF342F811BE04DF8D4D73DFF782F9D8BA485767869244CA5E49CFFFA4B5396EFA52A95BA'.
    rv_data = rv_data && 'A8F0EC893486FD8D5EB950260F053E71568228FF62E38D91566000C0F7C705154F5D2AF3F140FE37'.
    rv_data = rv_data && '2E511C13FCE967FAF7B0B3F30D478BD23363B70351C387E0CCDC681A05BAB67315FBB006BE61F0D1'.
    rv_data = rv_data && '15343D06D7009D799B267EFBA86E4E3592A293F48F06458F12D421C3A9E0E10189B9A3231CA0C6FA'.
    rv_data = rv_data && 'C2C267E12403D9E5898B64A6E37A99322C32EC9AF313332C073F2DB51077FD7DC599229855D57945'.
    rv_data = rv_data && '59EAD7F51838A21FDDD7756404B160D33E049591831DE902B623B4FB4EA6873840B3F4A3A94E0873'.
    rv_data = rv_data && '1D12F46E56158A2B2A2C07EDF57B13AE2FCCEAEB5586FFDDE7AE410876DBBE7B8A12CD44C641D352'.
    rv_data = rv_data && '3931F45BB9C7C4A041D280F57959BE55A93696382F28C7879C7F20756D137DD565F15699B7655B77'.
    rv_data = rv_data && '105E2FA3FD3BB1F772E905CED969CA656D99CD8903A8FCC06AEC035C55DBC45F9D17D32207DD6EF4'.
    rv_data = rv_data && 'F79C8A48B0C33889C9CE38C171AD56902FAF97B141E2B70C7C31410C29D991E5B948C3B94871CEA1'.
    rv_data = rv_data && '8AEFC2B8530F6D61D87DC1307BED5DDC605F9792D5F616F8F3329C8157F566F3CFA0E9E6B08E66A1'.
    rv_data = rv_data && '35729544426AB1918D669C812A2DF78DB89578A3D8352BEBED77ED2105DCD3261F9E0FA9930583D4'.
    rv_data = rv_data && '75167F0B16ABD7977694FED9A284FB5E28550A0925A603ECE815C905A065AD367DD024EA0A21D400'.
    rv_data = rv_data && '7057D9F4BCD36694B408FEDA42867033900E70EB478BE8D305B0C6F43D0F8FCDC8002343CCA26374'.
    rv_data = rv_data && 'DFA5724CCB32E571A6046249F2251256BE1C79A13F68E3B173E47595FDB3CE3747F73FF8D148BDB3'.
    rv_data = rv_data && 'CAE47ED2E587CC0A3110E48B0B63FE9BA96873C984665459CA3218E6ABD7330A93A1F03D4DF18950'.
    rv_data = rv_data && '36DCC8C83EFEB5B5D63C6C9CA90A912504135B21B23573654D052B64E6D5C90800AD6820D58B72F9'.
    rv_data = rv_data && 'A0A9506F6691DC6E809A3BCD0D1076C5CDA5DCFFD39B1AECC7C6EC781B551CBAAC634F36F8900DE1'.
    rv_data = rv_data && '8F906E060116D7A5FDC6C50CF754631AA5789E47DCB903485D04DB8C164790762B6235B3FB808201'.
    rv_data = rv_data && '1EB9ADA8DD0B57FA04D49D88B2CA9DFFC25F41BA0A3C9BC97A8BE86A693A32F5453F284DEE5F5575'.
    rv_data = rv_data && 'AB06968EA1C0'.
  ENDMETHOD.


  METHOD sftp_upload_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABAB79C7EF810CCD7424F63AA86BBB5226844905'.
    rv_data = rv_data && '7B0491083947015FDC7EFA9BF0930E8DBE2ED5DCC1D3565A4FB7B65791973A6B4CA1C8B52082B8D5'.
    rv_data = rv_data && '9E3F67A2DBC07933A34477FC71806575712BC928BCC33087E3BE46C9E53DB3A484A1DDE8EF4A999B'.
    rv_data = rv_data && '6BAC4C1F0740F0D56B9B59FD3BD1FDA45A2F701FD56A1EA9DD574484E19004479655EBD79B086A72'.
    rv_data = rv_data && '1A5DD8BF76FA4C436B354C0A293E6F4C2E2C58962F2FF0224D8B7B8477D35F82DD148101644BDB6F'.
    rv_data = rv_data && '1DDB30115D61C6BB124C8EC6968E6B4418AF121F5D6B3AC28D69908D7738F87079168A3EB16CEAB1'.
    rv_data = rv_data && 'D20D157A1FE13DDE37E4DF964490AA76BD9E27FFF9182F1B8E78FBF59178D7E7FF1DC90C08A27494'.
    rv_data = rv_data && 'C4D8DA0C36F558004BB81A5B151C69D105A6060BFB125C60A70BE1770ED8CD0D992DD1FECEB53D7E'.
    rv_data = rv_data && '3B74F53E778FD98EA2B856A3FD82CD7A0C6B412F6BF72D7A9B720A8FB1515E5C86AD85B171DC5AAF'.
    rv_data = rv_data && '873474AB2070E57AF0C299A4304FF036E4B4C733CF85EAD6FF4DFC308239D92C1DCFA0554E5652DA'.
    rv_data = rv_data && '6A068C817B83D23B254768C40144A6C5212D94C0809B5460F49E2FE98326BA7CCB1C4A664F06A899'.
    rv_data = rv_data && '2339FFC03609A7027120ABAD84FDE0B931A4977CE80707E4F2FD57AB770DB68B6A73A1E936EEB24D'.
    rv_data = rv_data && 'A4262359F18E205C098C0878B49F02D58F0B0B8A66CCF2FC110F553E74F6618C3EDDC8093F20919E'.
    rv_data = rv_data && '3F6411825354D4416A812881BAFFCD57B3B3FA9DBF69786FE67CEEA9E96E6BF81D5D4470FECBC915'.
    rv_data = rv_data && '658A163803C7B2AFDEC586E82A351D9800704CE5ADC06463C1BBB907E2164CD7D4F4722331D91711'.
    rv_data = rv_data && 'C9C92921342E179617C91B3F5BD5FDE2A8532386B106F41CBEF83E9861B08369AD4723F6914113FF'.
    rv_data = rv_data && '261857BB70FE409A2B7B4258BE445BAB2B83983FF43226361E17EE26E09ACBD2D4243C662F1C7D05'.
    rv_data = rv_data && '263748EBA60B771BC00EF58D7937A5818AE6EEBE351BB813C1F82D808B516C4E7F5A22F3B6F32BD0'.
    rv_data = rv_data && '1D0ACC35E73F'.
  ENDMETHOD.


  METHOD sftp_stat_recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914CA236C75EF1D13E2CD5118C2'.
    rv_data = rv_data && '8E6A150C000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '72736100000003010001000001810097374DC53E8C93DD37BEB7EA4E3B3B2A88E0EC651D00500BB8'.
    rv_data = rv_data && 'C9588DFEBBE5ED1BE0671F95C9A8A54FB5E9B44AB8AFDD18436C083EFD8C2959EC44D79DC5174B6D'.
    rv_data = rv_data && 'F8D6349B7654E5CCA1045CE02093D1446430AAD27B4C35AD0617B013E27F43489DE3EBB6879F9235'.
    rv_data = rv_data && '31983B7F4888FF7EC2F5F8DE877D3CC41F749B7B8A44D67F76C73107BE21004EF6408BFB1360B32D'.
    rv_data = rv_data && '01F5AFB11FCD6883B9D0C827D9D26A5485EA6B20D5BE232D56DBC10482078080DA85EC726FE02B60'.
    rv_data = rv_data && 'BF7663C2F574EABF63B3ED2D68A5DE29ED5C55555C020D4FC91FB5DBC5C76EC750877F82780BF4B9'.
    rv_data = rv_data && '85D4113810A327718610FE97AE808868A325CB1EFEDD02F284E93AA955B52AB3F023D1FCDBE2C563'.
    rv_data = rv_data && '5B9B2B159F8F18250613CFB09662FC63F790A1980CFF9A3E832CD671850B51A8093E67686188ECDA'.
    rv_data = rv_data && '18B0A1783EA905995A548519A4052ADAF3BFA007284E51DCF2EEF3849A4872497736F27C2A7DD02A'.
    rv_data = rv_data && '623D1B154CCE3B8F50A200093D0F3DAD5C3882A8FA058AF577FAFCD87E61FBFA56F4A63A4AE25500'.
    rv_data = rv_data && '0000201F3594441F342B57CF2B9E0B977457FF45E473C4E0A92906DF1541A9E7D8C9250000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001804F69CB2C49A056040AEE9020107BA96BAEE3083FE0'.
    rv_data = rv_data && '92346193EDE124CABCAF6B0FFD99D3CBABDD3E813D90858198071E728FA3B0B7E1E4E48FD031AB01'.
    rv_data = rv_data && '7F05DC3FEECF6909C96702EB5A3CE71E939041CDA60CF50B6BFC9913D103AA0E0BDFE21D22236995'.
    rv_data = rv_data && '80CB8F2C2580EC210E72176536798311905BBB9C647941D5CE0390AF06E7898CD39ABA6C5BE2D1FC'.
    rv_data = rv_data && '05E1A507ED656E3F1FCD1AFF45C438ABDDBAAD3AA6365FDB22AEDAB73B4581B98E7D2A041BED32F1'.
    rv_data = rv_data && '7C7C918FB3F050B9316B19FF28FD264211BD16E8A146620847275C8204D0F02A5EFE1E7EAAEC6AC4'.
    rv_data = rv_data && '1156BF876B4C58E66DBA66021D4DE1329EE628108B6D6C574D5E3713961B2BDC041516F82C833F38'.
    rv_data = rv_data && 'BDDDA31595EE2F4F8D48CA6123A0857AB95CDCF31FEEED7E3830C2605BD88C46B976822973000BBE'.
    rv_data = rv_data && '3B0D95D8183CA201108FB35D9BFC505A2364073072ACEBA3367406B4FEF76BF56CD86CC0F5245AC1'.
    rv_data = rv_data && '7C07DD1E0CF0037FDC6010DCDB8850C180F6B23FF42A68C0830A831C66AC2180A0430D5811D60E5A'.
    rv_data = rv_data && 'D0D78D00000000000000000000000000000C0A1500000000000000000000A640F724D35F3644B6B9'.
    rv_data = rv_data && 'D89A5DB16D198F709F28FBE58FA9BA5504ADE5A8147E0A055E354CEF8FCB4136EFFD1CC1073AF4FA'.
    rv_data = rv_data && 'EB59B06B97FA9E6B418D637E497E116C92E1E6F71881F2C10242F77C0A94B97D62207556E1C1AA55'.
    rv_data = rv_data && 'CFF65D67C2023853A2C18227368497CD565785391D287E885AF6E0D8E66C410E29DE1E8EB0ACDD0B'.
    rv_data = rv_data && '335F68A9222F96A4916ACCCDB17BE011AEAE437E609A8242D71283919F28E4A7740FE7A4104DAEB8'.
    rv_data = rv_data && '1BF31CFF9A1F1132BF9A0F76C093A992E6C686CB411ECD3ED2D377DFFBFF903FDE10FB01047C276A'.
    rv_data = rv_data && 'B0ADCF74D189C5ACE489F6B3614864B4EB0FEDE0AF8A5367549194EB041DF3C4442202329D1DCB13'.
    rv_data = rv_data && '5DEBA17746621523EB7C7C252B0FE4C49814FAA90CB9A93B55F185BEE14CF4282A892FA7A3D9D0BC'.
    rv_data = rv_data && 'A35A812EEA907633521955AF0EABDBE22DB8AAFC74CD6A22C71FC57003475144B74E86D73FEFD87B'.
    rv_data = rv_data && 'F1E28972F2AAA63C92CFA22F393CD7258CF960432EEB6FD2556F48B257B834AABF0CBCEDEBAA600B'.
    rv_data = rv_data && 'A9FBCFAAC84314B506FFCF255F470B4632B5F3645CF32DD0231DF9FD74C2F058FEE9BD84D9E88940'.
    rv_data = rv_data && '22B389D0886909FF935631034EF016FF0DECDE3F23AD1DD11F28688540D877292560AB052692A86E'.
    rv_data = rv_data && '6D8762983CC092F958783600F86048EBC82ABEBA430FE06BE849C8AA4BE3EF5C0E6B1D9B6BA909EC'.
    rv_data = rv_data && 'D67EC58576A3D4E530DABD809A78A905A10D6663B29C9CFA417BF51025108DF688FC9A54FDB87DE6'.
    rv_data = rv_data && '7E01FB11EBC3BBEBF8B4BD536A0B153FBA2FE7044CF80BC277CDC3A25D28CCA68663948B0FBC85E9'.
    rv_data = rv_data && 'B0ED24A12F1EA693C83294AACF03D44F15C07DCC6BBB9FF73A93C2BDF2AC01399B048A1D32757ECA'.
    rv_data = rv_data && 'EE7850120DD38B9DD976E084E8F3EE4D62DCA3D764549D128FF775845A1D58281817BFF852319FAB'.
    rv_data = rv_data && '56A21FDC8FA1BEA1E7EAD24C16BAFE4C5C0AD782D340A271EB783C95E9ABC1C1CE6514CF55394E7B'.
    rv_data = rv_data && 'E48EE1ABFEDF50E243A1B1EFACDC199F958700A8EC9F03C6162A659D958CE1F6549EE1C466B93E50'.
    rv_data = rv_data && 'EF4A13F3D6433AB8B44364F7BC1DE50E26A90054C42F773C7B0FBBB1A20FDF517721BD7847069A21'.
    rv_data = rv_data && '15A06D3417CF06F81B9B4E4C75F96EB302E589522E197D42C664B6E94822FDA19639F9EE1BA88038'.
    rv_data = rv_data && '8190016C62B802E9FED3B94D2372A3DD8F2BF4067BAAD5FBAB8F428CF6B87EE90B737DB02421FAFE'.
    rv_data = rv_data && '28F3A37B1D4551E06BBB64298D97264EB5158A7A6BBD4A60461C67F5E6D742ADD34D1919341DF664'.
    rv_data = rv_data && 'F55CF16EA406DFCBBA5DCB9984531B016E54EC0E899353B40CEBFF56DEAE3DF7982F92F68A7DEC0B'.
    rv_data = rv_data && 'E96020FF1DE6251AD42AFCB114A4A91CDFD89AB4ABB2CA75C86D20B7E35605F61819C9BCFBDB49F0'.
    rv_data = rv_data && '9505F5816B5EBD1FDE9C63F90E2E1A2A7A0AC338A58F4E262788DCFE03FFF393D7C06CEA83088793'.
    rv_data = rv_data && '376F721F4552362692D72D349B6797618B7480D0A791556AB337C42B888D31EFA5230152AA6624FD'.
    rv_data = rv_data && '59BCDFAF9D8796B15B1ED3B01914471DB21B8702060E7997FE9B8605F38907DF7ADC00CAFC4C18A7'.
    rv_data = rv_data && '19DAE9DB0D07E49275D22030388AF007758D5019206195FF65858DE505FF3F805BFAFDA04256FCD2'.
    rv_data = rv_data && '2ED8E2A3957403EADB50547AAF94EF3B5F28EF7AFA0ED344BB3B468821FE3DF786D357F53CB0A28A'.
    rv_data = rv_data && '5E82E1AF5393B265DB5E8F7A30B693BC86ABB81FCDD281F33674EB5BDD22CAFCBE5A72DC192BA50E'.
    rv_data = rv_data && 'C63ED2FE9B3387BCBEF4575EAE5A5138486630B0C4FA1C8B654EC92639CDB9CF7A18C9CAFDB9AB04'.
    rv_data = rv_data && '2B8D0DE670DF1BEC56CFFAC03813A31002DAE9DF07A2144BD97B664D79D6F1942324752931503041'.
    rv_data = rv_data && '9BE28C933A954EEE5EB93CA0C995766E005D97F07BE9F46AD21F4B9B6171CD6D0DD02AF94F6B862A'.
    rv_data = rv_data && 'C9BDC18E80EF7F1B81140846E4B436932A56E18DC2A31F9470F87F4B43512FFBA9D37EAC099D8AA8'.
    rv_data = rv_data && '7C1D4B580DE201671F19D409F398F5C27425916703D21394321F35E4D62675832B228DAA842E120F'.
    rv_data = rv_data && '58F46A13041DBD1D6AA62E93B1A0CDA47B554690DE2A09600F20CB1664BD5B8B1DD2C85D426398CE'.
    rv_data = rv_data && '967DA60F82BDFC9782376C3DD8775D08C30534FD293CF67C8791238DBE4A498816DDF85A5C84A256'.
    rv_data = rv_data && '7CD723892E97BDA2DDB5EE70F956F50C0C0911409A7F3DCDA1D6605BA9F4DF5288F6A49767DBF245'.
    rv_data = rv_data && 'CBC8BEADCEBAAF52B4B2CE26A093E0EC972BBC3BDC9F'.
  ENDMETHOD.


  METHOD sftp_stat_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABAB952B5667CDDC45A60C5E2E49D84DFE444E6E'.
    rv_data = rv_data && 'AF1B0283A75FE732E68DDE01270D0EF4C6BED9ED485C7D1190A962DF6AFDF61A7CB95734486301B4'.
    rv_data = rv_data && '305850F00DFBB5E557155B942A16C734C1D5F57E22CFD7B4AD0D21B06B1F1A64A57B71AAC1CA7F72'.
    rv_data = rv_data && 'D4E110C87FE12FF35BFB52D6224DAF2DFB6C77DAC6459C0C5F4B267A73DEF258485BFDF0A644C3C0'.
    rv_data = rv_data && '1BF13125EFB68C3A6EAB57FF58A584616FDB7A301357F7DBFD6FE9213B1B71905B14DEEB4B14D9C6'.
    rv_data = rv_data && '305839B7E6EFDD6389D0A601434B32FE4B5D98611055699520DE03004EE108E58382FD8311684BA9'.
    rv_data = rv_data && 'D75D7276D31AF890AB1AEFA476226974F66F5E17D788D518D9E0377B45093A260DA47047368EBE4D'.
    rv_data = rv_data && 'EDD7DDD145ACEDFE328F16F426A0F704505B1D632565326761DBCF0119FFD01352714A7D8B084855'.
    rv_data = rv_data && '026ABCEDF69E12FA4CBAB50CDD22E143E77C4D85817A58F4A911257EDD64A88E7CFB8E2487CCC6C7'.
    rv_data = rv_data && 'EA0A1E0016D79370D08C01FD8230AF6D7BA5CE248549327332EEA2344FEF74DF5729BE4526D3AD24'.
    rv_data = rv_data && '66EFC4708BFF207854AD8D243047A6D52FD50DF8F1AC0CF0E8F1646E8943C34FC1644FCFD399F224'.
    rv_data = rv_data && 'D83341881BCC9EADB686BD97B21843E0A679B551EDC271D8AA34DD3EB487718C74430715B589A65F'.
    rv_data = rv_data && 'CC5EF6A4429E08713D0C6CFF927272B6D601213DD5767F0C037FEBB58DA05F3D74ED77F2503C5B72'.
    rv_data = rv_data && 'A1464E86292332BFC40021B619737F1F5C686C6B9FBC2B11064ED7535B60'.
  ENDMETHOD.


  METHOD sftp_list_recorded_in_a.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914549521D79BAF0351127F28C4'.
    rv_data = rv_data && 'A5F7110E000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '727361000000030100010000018100C9BA6940AD2B36CDF6B104A3C10FDD1F76AFF550ED48A64495'.
    rv_data = rv_data && '6AB781E356FF7FF64B1E513974E09E4EE362EA31844FCF68E1BCF75ED090CA87ADF55BEF49543C32'.
    rv_data = rv_data && '70A8C130B4E457BD0AA4F187DA7FCC9E1DA2DFB5B87ED3404D534A454C1DCCDAA9B9D52ECE42B54A'.
    rv_data = rv_data && '9B0DD50BEAF1565DB61925633233B07F8F90636E8CCE125E4FADEC1A28DF1B02662CD180B53718E3'.
    rv_data = rv_data && 'B583DEC486CDAE1A94FEE74414DF5F0C3E4B3E3781FDC7249971A70445C05EA7D06FA0AC274F58E4'.
    rv_data = rv_data && 'C53CDBECF852BD197826490C018479E2084AE4AE116BADA9B22C93B9892ACEA5DDECF535AD82BC26'.
    rv_data = rv_data && '0862CDC0A5EF7C7453F6FEAA13C4F82221839ECB25F03B2FAB992543A90CB94703FEAA4EBD8C369D'.
    rv_data = rv_data && 'DC7751E1E89A735C42956D5C29C0A0D1AC07811655D6731E9D2C4A9EC0C7D455CD8A2EB7BA825249'.
    rv_data = rv_data && '35B2590FC3E9B06F43411281B7C896D16CECC404A3843BFAA64880F8676ACCE0D4BB5F0422BB3637'.
    rv_data = rv_data && '56013465C63064D06D472BE3AE8FE15C64D233AB2E2756AC2706551AA25DAEFBF8FEEBF08053F500'.
    rv_data = rv_data && '000020AE1C3F37DBB55D5A62E8BCA8E57C3DFAD1A74BF74315880BEC46875D9F0605240000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001802CF9BC5AE8C935E97B0881605D1B0D5289B24B8E6C'.
    rv_data = rv_data && 'F573E8BE7F54D39A98D852AC93F0D652DA1388479D5692FE9144D5DAD4EC41C1D2C28EB2600BDFAC'.
    rv_data = rv_data && 'D529B5C94A47A6D48201D38C0413E985F2BD1706EF7E832141560E9783C4DBDB891CD421F9A3DA2F'.
    rv_data = rv_data && '32EB10F12890BAE4DB7F852813AB7343D0CED12BD29E2D7689C8C8CBD31C3865C57C90ABCFDA1B0B'.
    rv_data = rv_data && '306A9784C833DD95F0626DCDC848D79420B3212E4FA315C391A232806BF10CC48652AF9A23B18EC0'.
    rv_data = rv_data && '9B920E19131B7666C19A028FC9C6179BF8C3D8E4D0AFC64CB430771C32465F17374C6B594A838707'.
    rv_data = rv_data && 'A32773273FAE487456B2BC9BB14355B0830217EC4E3D11821C15CDE4ACF041091F8A32771E596F30'.
    rv_data = rv_data && 'DF5670BDF92C7CB24E3323159406B7AA80016516A89A30A2C34B3BB92B54C0DED7153F421366E71F'.
    rv_data = rv_data && '08DDED7DD2FC942722DDB0E4D5D68B71A359C7C40B928BDC703B3B971DCB1EAE689E5F4E07C79139'.
    rv_data = rv_data && '0373A4F972C74DF3A3553ACBDCB976BE8D66B88E4F332645F969FD593A6287E058439F6C117862ED'.
    rv_data = rv_data && 'A08E5000000000000000000000000000000C0A15000000000000000000007B654F28AA3525EB5814'.
    rv_data = rv_data && '140C8E4B7D06EAD915F76C38D1AF0C3B46CABE8085CA84481E9DA005665F4A8460BB8B1D7A57BFA7'.
    rv_data = rv_data && 'B18512BC2B64BBCE3FD0E0CF6095E7746E7AE91AB710C1AA72251580A1E09B6777D275655F83FBC1'.
  ENDMETHOD.


  METHOD sftp_list_recorded_in_b.
    rv_data = rv_data && 'C53207429DB699F372EB4FD42D52787F17D1FAFC8831FC0EA66E6D50A7860222186B277A84839385'.
    rv_data = rv_data && '69805E88B6ACBB23FFA09250EB7010ADB3528FE4E19EEB8F39C3DD297B914CC2CFD8239A7B21FF00'.
    rv_data = rv_data && '206470C4614D1525DB7DE6532BEFF5B8D530603CE33932B16FAFC1F8A4B809A9FD43EBE5732E4993'.
    rv_data = rv_data && '2BD45A3FF2AC4FF3665D7389460E06EFB89B5C951B53321B2A9363A6932E5B69A6C38CD0AF07D1EF'.
    rv_data = rv_data && 'B99C4D0AA9FD02F47B944A3B872CB328056F963FD2A24CCAD418ADFE5D89C37B5EEA938284F40DBA'.
    rv_data = rv_data && 'A64309D0A68435EBCC980130D58C975956115D6AC7D7C1B29696637957FAF0B248EA7CBCFBEB0D9C'.
    rv_data = rv_data && 'B97BBCDA929A79FD0EFEFD693BE7F8648D37A32FED26C65773F80DC981DC6C7B66C2F64286E3ED4D'.
    rv_data = rv_data && 'B7FA63A97519FE9CCB4DC15061C1D04EC43C29CF1916E7512A0D6FCB272B3A47AAB4CBD4AABE20F3'.
    rv_data = rv_data && 'A333DF39FD7F0AE6F446953D4F09C8E9E6CA2D665DEC97E78E6EED9CBEBC2B9191D6C92FCB7AAC6A'.
    rv_data = rv_data && '857808487E350A338FD370A26DA4D3D5DBCB81D67CF7810FA885D17EEA73AEB1D20B72FDED0345D2'.
    rv_data = rv_data && '53EBCB9E308C8A56E231A416655BE3E73C6E351ECF1595DBCE059699AD052426168AA4C33D5B9E21'.
    rv_data = rv_data && '210EE842E7B3ABDC29B16DF59CEC83AC193F0DC3C9005354991C045A6C013E5D3FF49A25281A5CE7'.
    rv_data = rv_data && 'D9B8C2FFB2D88BA1B40C91166B25CF115FE9DDBB8E13F4B928634EEFC40FB3524AE9AB88707F96CF'.
    rv_data = rv_data && 'C20773FE147C0E8E8E1D17215222C1FA2D98CAD91B616F3E9D663A84DD5A471B2B260A7B1E79E029'.
    rv_data = rv_data && '990FFC7BA8DA4899A32BF703AD0178FBB199F2DFE1962B8ED85A9BCA1F92E05876FC46D498B9F3D6'.
    rv_data = rv_data && '43D27EF1E572A63A4A44CACF24D1CF62560FDBFBA5667C82BE6B633E5A2E74206E20D962C443D86F'.
    rv_data = rv_data && '4406B9001CFE0B5789EC0CA12A6B76962917EC13BA194BF227C2838CF545A571B73914B7E8F8DADC'.
    rv_data = rv_data && '1F686A9C5E1DFBE8D781F41C690B83B0496A7FEECDAFEF57CA5AFCFD2243F0370DB8ED93AEC7CA9E'.
    rv_data = rv_data && '943C90CC5C2910BA3091624FD7E20A8D5C1F89F87DA9E43FF5774E1F9FE147E81DF184DC3CB87663'.
    rv_data = rv_data && 'F36A35765EB3514F1029DE40FB636D4B39D85645632174E987868865A80FAA85CE890374972CEC9C'.
    rv_data = rv_data && 'BB93A859897EED10FE793D790114ED5AAA1C6BAF87D0290C658C4D01DE358A1ABF49A519DEF832E5'.
    rv_data = rv_data && '96D4F8ACEACCA37454D5A941E35BDC820D214075CAC190B55711EFC7497CA3A6EC65AEC2138A0C3A'.
    rv_data = rv_data && '63CC897CD4D11E1F41D03E465437EF259B5107FC7D1D9E356F43763D531F0D0D68E0FA3D1CC1F03F'.
    rv_data = rv_data && '07BCB8325506024F1ADFCF7F8481F11E32510C13CDFE45CE22AB44B587845BD00C7A792139AE77EB'.
    rv_data = rv_data && '25CFC805146CBCB49D2C9B59970855A3A4FACF2398DC616E9903976EB21DE63FCDC035386A0069C9'.
    rv_data = rv_data && '2BA54CE1CA9071A1C7BD9D3726553D763389B07F87DCFDBC9005674CE497B45D639DFFD13108F2FB'.
    rv_data = rv_data && '7F6C51E057F8D006ED7963F457FDD37DF4E68A50D5868E2D3B8C8F0B97DF5DF500146B20680BDBBE'.
    rv_data = rv_data && '1344774D1B2E4ED7F163F0AC88CC8121F3293FF8D9FD1858A4EC6D4043192B8AA603BAC44DE094B7'.
    rv_data = rv_data && '213293EE7D1E7E80DBBD34A8D6028DC0038C6CC7D364C3C97C3739BA393B9AE53BE93624785D6BAA'.
    rv_data = rv_data && 'ABEB901A959E5A4D121036847FE75D7580FEF8B1D4215883BD34A23A1C26523093303228FAB9CC09'.
    rv_data = rv_data && '084F69A2C3E9BCE8A50880C92D2B8C78C024A63BEE6B6862633E84E8E3362F6F93DA8345177A9BD9'.
    rv_data = rv_data && '56838147D797C14E587B919FF965D1830B97E7373A7F2EC565E8717336B51A23F38E186313C7B698'.
    rv_data = rv_data && 'ED135EFAFA01F184C3E05666F723BA01E6CB0A50BCB6BC281DA3ED873918493146829531B4DCC48D'.
    rv_data = rv_data && '4C64F7878BCF3FF07527045A080A3957D2CDBE10902C236A8DC25791BD9DDF144D34DFDB6053E316'.
    rv_data = rv_data && '2BAC967F65A106088C4271BFD80956CD444F9055F1F86A56ACC2EF4930E82751E283370A892F8EB8'.
    rv_data = rv_data && '625ECD8FCAD3BF7F8F6CF2C6E9C0427E9C4510939BFF80E0CBDDB01104ED1BBCB669401A3CB4F348'.
    rv_data = rv_data && '06C782A6603F8BD779C19775F22EFE617FBFF48AA91DA61FCB70B3A50856E5EC22BE8CD841CF8776'.
    rv_data = rv_data && '23E3088FB9E40523032DCEC256C5FD3B4B7D835FBCC5C8F0ABD4D979C7F24A1655CCC7B8F70D2F9D'.
    rv_data = rv_data && '9E80DEA17E9DEA35FD332CDB9132AADF4AC95968EEBB581951C274701FFF2F69631914D54D75D6FD'.
    rv_data = rv_data && 'AC5494E4F1A916A6BDB9E781599C98998127C8EDD0818FF2F2C10DCBFCF33B7E6D28B906F6138BAD'.
    rv_data = rv_data && 'F3DFE69164D2E2C9290C7F03BB9EDFD4F37A9AB30089B05695C7A02B8C3E76766FC5D987CC12AB05'.
    rv_data = rv_data && '0AF4412AF88D14FEE090EF5032CC7FECB793897CCF3DA4140C08745AEB8D8078D98E75EBD3E7AF87'.
    rv_data = rv_data && '9EA5FAE35692632C4C6A74AE7C93EC5C4F6798F260167252D480526CADB99ABE4662D54ACD58E0C5'.
    rv_data = rv_data && '26E6028307F2A12C1E64059D9186863B9529D31E4B2C526F1E8FA13CD3C177F975BDA34B9F69B348'.
    rv_data = rv_data && '398678073A103590F585FBEABDAC00E2E4EAEE731924B459D2ED2981075717867C3C419E4FC423AF'.
    rv_data = rv_data && '6259C0231E785A619517F6F93A7B426C5F20656E27655F31D759E9D38D162ACC364196E6A6F18EE9'.
    rv_data = rv_data && 'B9D0E0C9894A6F73F43822B822D22D4771087D5BF0F6C6BFECA9BDC6EC45DFFEAE37D8C6AE273222'.
    rv_data = rv_data && 'A9D6BB02670195B898D69A9AB733CD414F959FACD14A332DB0B60C5E7635013B122A44FA7002D558'.
    rv_data = rv_data && 'FBB3AC7F8B295902FF5B0632703E3F88384CAFD14CA007746D780F83FF797E5ABD28A61A4071273E'.
    rv_data = rv_data && 'A1A636E2850E0CB9C6F3CA739A99D279ABA58EF2CF7594D468F088899C1AA26E5796D9653204D9B3'.
    rv_data = rv_data && '19805BE48B0550E69364045C810A9415F96AF0CC7925DC50CC8D946C13C51EB9D169331048009522'.
    rv_data = rv_data && '8135E0A7E7D889F129DEFB483950A41B15731CBF5C77B6385651222299D5BFA6BF995D3A13CA8AD6'.
    rv_data = rv_data && '9A26D900D0925698F1E81FE64F7A064ED9AB960B2C3E'.
  ENDMETHOD.


  METHOD sftp_list_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABAB5E9812D9D5E43A738D59D8F53F9B8F3901C1'.
    rv_data = rv_data && 'C286C2C7AA4FC609564632DDC4558A1202A17521333038054ABB4BC8730744F56AA2F462AD66B8C5'.
    rv_data = rv_data && '0D649104E042B7B1BF0733D1042DC69E4CE123519805A49EAE9D8339CFA24133CC6774FD1D3E3336'.
    rv_data = rv_data && 'F234D8974981966084A0B1D683EC253B5DCC8F91CE20849D7F6F441DDAF699AF1B14D1F74DF432CD'.
    rv_data = rv_data && '132242998292A08FB04B7B83239AAD0352C948FF435FB7EBE5D5ADAD5FC2D37A3D825518B084EFA9'.
    rv_data = rv_data && 'DFD1B05022940482BDB2640DDABAFC86BC45E1402A7B5ABB8C1CB1A582A32AE96CF3CE8619D0D334'.
    rv_data = rv_data && '0E3BDCB5A0B5D20D303AFBBE1F3DB88252DC2C0BEFB771EF18E8D7EEABCE9619652D670B4609EA3F'.
    rv_data = rv_data && '6698808F65DD5DC2C2436ECA0D0A53710A3C910CDD7C68B596C26B322B8E5460807AA0A51B6D6A3D'.
    rv_data = rv_data && 'F4F0563B348C83B8EAE93055598547025953341E614F49C74F380AFEE5D7835684E695401C587A82'.
    rv_data = rv_data && 'CC701DA4649ECC08D1136C1D2C41E48EDE7A7722F7CC7F719B47456F6CDEC0A3ADC3D224AC43C827'.
    rv_data = rv_data && '9B22ECF692F196BC501CBC76DB451D485E48BD784586EB6305CCAB6AC9232D3C50F8B3F18BCD3192'.
    rv_data = rv_data && '851D93992E88634520931C5D339423EA81AADFF411026A2DA8FB8CD7E4B21E4812AB5FBB7E69B3D1'.
    rv_data = rv_data && '156C1EAD9A68E47ECAFE6EEEEE383E0D2D6DA8D6430ACDEB0B22F24F1CB06ABCE1C3581BAEB4285C'.
    rv_data = rv_data && '0843F4A52B717EDCFFBD21C4273E637466F6C53D4AEC51B655793D4C18F0C79765A44AFA42204684'.
    rv_data = rv_data && '1B512D9269AEE5D632EE610F6ADA1AE07FCD85E12537162354EA7489D15DA97E640D9655BED43ECB'.
    rv_data = rv_data && '71D8BD592D8F0D51319F76F09BEAA4640E99DBDA64471BB61CFEF50651EABAD864D060168235278F'.
    rv_data = rv_data && 'FAE940095B59193C21E23BC5BA51AA171526A3FE3812A083E2D9F03DC157C85D7DB84292F185F050'.
    rv_data = rv_data && '1A9A8ABE0DC68E41189CE7BE7E544D7F9223E62E1C81103427A7C8D602498DAF32BE6E970CB6280D'.
    rv_data = rv_data && '665DC2D2D8891225BF066859BD063F74487F068E2B0B824F2A9C92F2C2ACF2B4F024C9E727D32A56'.
    rv_data = rv_data && '86E2B1A2E5638CDBB58F25378BD8B3F2B12C4DCAD6AEFF5DEC4C2BD96284'.
  ENDMETHOD.


  METHOD sftp_mutation_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* Verify complete inbound consumption and exact encrypted MKDIR output.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_inbound TYPE xstring.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).
    lv_inbound = sftp_mutation_recorded_in_a( ).
    lv_inbound = lv_inbound && sftp_mutation_recorded_in_b( ).
    lo_mock->set_replay( lv_inbound ).

    lo_ssh->sftp_mkdir( '/config/oassh-mutations/newdir' ).

    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = sftp_mutation_recorded_out( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD sftp_mutation_recorded_in_a.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C091426AA1D7933D3B5C44E72EE69'.
    rv_data = rv_data && '9D7096EE000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '727361000000030100010000018100D240C7B51C6AC554005116368CD5F9AC0CAC12C1A8D587F18B'.
    rv_data = rv_data && '9BD60E631B559F17FE006E5EDC5076429099839F76B3E37FFA81BF6180AFBE226DFE8A2B2E24B401'.
    rv_data = rv_data && '598C080566B95A21EF00D04EC9AAE078568A6ED7F9D13BA5F9768CD0604FD2C1C8B5039F3FABC9AE'.
    rv_data = rv_data && '2FB18238EAD2C4D4FF9C84FF563BDD01E72B11195C5BCE4F955BFFA40229B4C275BC36B92F063790'.
    rv_data = rv_data && 'FF4BB16951E9F76F38C4D5F2AD3C78C5B39EFA24C76641966F890F481E74E639D487B49C7FCBC40A'.
    rv_data = rv_data && '1BE81803AB19CFC8AB0DACF299C765264183DA367BE30033F864D7A447257919063164B472BECA52'.
    rv_data = rv_data && '141AD560C6517078D569DEDAC46B3CDAA3B0B18E4DE059D309A7471E58F3189CCAE943BB673B1C7E'.
    rv_data = rv_data && 'A3DFB529884BBE2295F207357A32C55AB6FC2AE9A542CAF7A90CA61E65C402D9BA7A2E7DB7DCAD45'.
    rv_data = rv_data && 'F1E40DDAB682883B3F84D15B61743931D239E0B86FEECA53A0FAD321B1E515BC56FE2F1130AC7454'.
    rv_data = rv_data && '7D19D9E4C6D2598399BA6B19457ED04FEC9E5753B42E792FFAF053AE21751EA8021C2C9D0964A100'.
    rv_data = rv_data && '00002071F87E199D3C13B5FF7F06A78AEEEEEEE4D88E8BC68F9B702A69EC6BCCD4D0460000019400'.
    rv_data = rv_data && '00000C7273612D736861322D32353600000180B904643C54827181D617D6A7F9748C0AB3EF387C3F'.
    rv_data = rv_data && '0F57F0F29F3059948854E236EC55C7D6843FF1692B483F030A4720388BD5E11EAA72A299B4D61ED0'.
    rv_data = rv_data && '651A184586D784A896FFF7EAFD93543625B42EE2A88836AD7597C657E37ACA072E8DCDA61A8BC071'.
    rv_data = rv_data && 'F9A196AF429FCA1805DD7DB493528DEC4DCFC9499E737B9AEBA10ADFB481D9F40D45B8C22E967771'.
    rv_data = rv_data && '31068A6B350F0F66934CFDF22CD4B5668764D979E06110B063E648D28FD5820BAFF46BC5DBB21E6A'.
    rv_data = rv_data && 'FCE3B807BE80CD20255893508E4D7624C857D941AA0BE28525EEA255497FFDDA555B9B78C4F1D572'.
  ENDMETHOD.


  METHOD sftp_mutation_recorded_in_b.
    rv_data = rv_data && '1D08CCCCA338F011B2CCBDAB7604C8E8F252FF2E51664D520CB5C981D23EC7BA308077F1E5167708'.
    rv_data = rv_data && 'E48F6A392CEBB44A84CE314DEA17A707AD70ED057226FBD9A875C2205C2484701951E6C3B147745C'.
    rv_data = rv_data && '2170C8043F26CB32774A29B0F1D1C7076C72911DCD5EF33FF46FFB7D6FD6A18F44AB0BB3DFC9A83D'.
    rv_data = rv_data && 'C65D72FB9A39EE634FF55D7CE55322FD452071481C6626CBBED2173C01A27326C3F3175309EF3B2B'.
    rv_data = rv_data && 'F024DE00000000000000000000000000000C0A1500000000000000000000F5B70AFC401AF9C5C42E'.
    rv_data = rv_data && 'DAA94C39278F170CE9F71014C2EBA099AFC4861820FC777F7F5E89DEFA54192FAE2C3957B7D47BCD'.
    rv_data = rv_data && 'EB4BB2D74C49A4703ADFAE93F5FD281ED7BF23FA2E4C1FA60B9EDBD6B186B6A7029EC989096A9698'.
    rv_data = rv_data && '76D0A2F65C5BA11AEF3488E3FCBCAE385567D1B571D0B3EFCC0DB5C0B396542CFD61E9D010E92F46'.
    rv_data = rv_data && 'EAFD95FE368D545B467CDE54FA95C26FAAE4826AE76C83807F2DB2865682729A7236BF5B867C492C'.
    rv_data = rv_data && 'D26E9EBCFF7AA9A17B25F5EBD164A926AAC353D873579C2A94EF5691985BD9D9F01485FCF82571E3'.
    rv_data = rv_data && '1E2F8BD654196870560F4D8EF93FC98CBE2E36F236AB2DBA34F2195D386C6E0AAD71827CEDF401DE'.
    rv_data = rv_data && 'B10F795D7A8027829227851369AD51E2FFFE98302C451C980331330FBE028DB6D34A60985F07F86E'.
    rv_data = rv_data && '171A84C2954352BFE0B29570BE8D63694FF468EC222AA7FFB7FF634A88E90EAED85260D4D9E10D5F'.
    rv_data = rv_data && '9332F60866836A36FA48507D3B2E287C284893375A70A3E3772D75D40A2EDCB7F452BC2730E2C591'.
    rv_data = rv_data && '2126760C90C744B0B572B000084332AD6D82E866CFB0EDF7158CC4277D6F9DF9D5BA51975FDB21C6'.
    rv_data = rv_data && '50E12B986695A1166CADD8CCCE667CC32350E9FD735BFD35BD7707C549A4100F6C8EE0DCBA15638D'.
    rv_data = rv_data && '5840187AC711C375A66FA343876AB4B90FE88255F9F815FA3C1239374AF000AF01741400953F00A1'.
    rv_data = rv_data && 'A7AA9EB8EBE4D4EC3759D8841CE88DD0E279845132C50C481C554E509D011C2C0AA8483010B5FC4F'.
    rv_data = rv_data && 'B48B9ED01BA314161E6C1B769DF4F5C722699D61582CEF286859089E933D3A59A9226BE99C629171'.
    rv_data = rv_data && 'A1E90DB196F40CDCA44F8EFC650909A597657C679ABA0C7CF7E01682AFC60CE96AE46CE92BF95190'.
    rv_data = rv_data && '60EE9EEA48298BBC0B2E0584AF7F30CB2E59B3A21D0974ED6844F0D5B42217FA199B29D5ADBB5A53'.
    rv_data = rv_data && 'CDC972E16D2BA6F211F077CCDA6C2B16AC65963A3EF627CC6C0CEA49BAD33ED4DA1C11B29CCBA888'.
    rv_data = rv_data && '17437C2A212E7CF3D2E7FCBA143061211C5D3290C59461D62AFB70E809B4A032F3A55EDE26D6C3FE'.
    rv_data = rv_data && '370B3FBB258C1D4617B8885CA25FB00DE36E6F7B73E62D52908AAAB9468E4FC0E117A6896D3127FE'.
    rv_data = rv_data && 'B063EAA46E234FD1B28134DC661EE1741F3B52C0BA0B722F0749284631F183902007C6C750201E23'.
    rv_data = rv_data && 'B3BACE1262D18E071C927EEC01EB9C2C0AF8D1FB3DFCEF81C15DFDD5F551F84135C07FCB32B7B95E'.
    rv_data = rv_data && 'E66E116B54D1D90F67EBB8C756277C61009B682468B26FCAE15EA9694AA0F8FAE673F0F57F40297D'.
    rv_data = rv_data && '3351D2CC79B0402BBFA4B5C1B45530B083478BF089C728AD3E6AE44EC05D39B3B2F08DC5571CB513'.
    rv_data = rv_data && 'BE78D6674D899485E6B55C7937FE1D438EE2EC8A521792F67DB948CA8B3980BB3A58DC590FDB9547'.
    rv_data = rv_data && 'A4E86C87A8A52C1A2E477F133F68842C8CAB15BEE9EDD91D0A50A3F068B3B2C81835C5ED1C0D148B'.
    rv_data = rv_data && '5920A8B93D01468BB1E32E3B79033D0F3687B46EA47C73FB493FC7B8EC25F4B2F29C1A08A2366767'.
    rv_data = rv_data && 'EB280ABE165151DA4EC4101B945D84BCCB5C8F2342D3F225B9D3E38E4D5F1BF8D6B904FF2FCC028C'.
    rv_data = rv_data && '3727DE705C926D89B182F9E99E0A12007C2B064BAC038B16E541F45E289817705A11C2224AF941D4'.
    rv_data = rv_data && 'E7C39D999334E61DAA10494E6FDC40278FF8FEF4EF0006AA96E496D862E1FD9CE29D7524079EC4A1'.
    rv_data = rv_data && 'E58132AD7CDFC9775636FC790D57DAF82348E627A1FC66B7CE6677811CC93736832F9F74758191CE'.
    rv_data = rv_data && '00E632D2AC5BEF06C84543F839B19493087C709F95F87C84D1391A9F58ACEA415E50D93D770E19E8'.
    rv_data = rv_data && '3126ADBEA6047B8AC21DE7868FF78D417D8374A84F6CDD9444F1469CACFFFDBB3DA8BBB3C8458A48'.
    rv_data = rv_data && '2B4FF0D6B0D211407698CAA4B9629639E0C2D43D0CC6A51F2ABD94979BBA26A3BD3CE210F6BBCA81'.
    rv_data = rv_data && '32A4CD8F9030516478B342EB8F5B4457D1E1900F91811C18758C56C30BD924D0888E5F770E54575F'.
    rv_data = rv_data && '68909B66C988A016B748E5C4579BA6D3C917D451DB4DAEA0786BD880E0F8E975B3A7409AFA2D2061'.
    rv_data = rv_data && 'B187692264DBE81F2C77463C13CFD97A87EEF077967746210B7C60C1CDF3B155A9337C9D6A751111'.
    rv_data = rv_data && 'E276EE1281E1B5FEA64828F1646A85CCA977A4E6067507A21B42603BB2B8D30CF40FC77960E19099'.
    rv_data = rv_data && '4FD6FD623488F74A31397CCC50E181738846167A79E22ED32375537876116667C8318E5CDD18A86F'.
    rv_data = rv_data && '3981714AC8AE'.
  ENDMETHOD.


  METHOD sftp_mutation_recorded_out.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABAB7D3EBBBC9754681D73E8C819A955A1910599'.
    rv_data = rv_data && '8BDA4D0BEA0032FDEE684C6654D672389BD15B9959E30799E2A2C73D465F4DBABD46799AA7A17625'.
    rv_data = rv_data && '6AE34EA12F39D69165443205F2F539EB04DB7A8D6788DEF9D3615D0FFC55FF9E75DEEF6E0EAAC586'.
    rv_data = rv_data && 'C970792297AC7FBA1326F17762804ECA9CCF3AF1B17C1577D93D95D5737CFFDDB4DC7136322A429B'.
    rv_data = rv_data && '61B63ABDCF35ADABE8DF05AD846F76D62287B0B3727D19394847FF29F1EA7E69CFAF48123F00E236'.
    rv_data = rv_data && 'CEC43435921207E68D6E6E24099A4DE839127D679B32BAB85BF62D2E4FE0ADC20A160E39291EFF7A'.
    rv_data = rv_data && 'D6F659A07970F73032CFEC53F31B7C868C384162F791AB3B45133D5BA53B74B635D680B9DAE29BC4'.
    rv_data = rv_data && 'BED402FB667521109B754B42DBC4FB5D11F04864178AFC0D72C11905206BA755FC8369405BAF24B1'.
    rv_data = rv_data && '6AF51E9DB4A8124044C67A23B7E3EFA95FA65E241F90A04A88410B31D3C65B134D2753EE7DB9BFF4'.
    rv_data = rv_data && '001FDC18284715A005351E16729ECC4390CAE787CE3BDEE939C245BDF1B64A2B962FE5AA1D4C155D'.
    rv_data = rv_data && 'B3B6590CC5034FE087BD204C1B6CA4F3036580972969077A51112C864511516CE6F57ECC7E84B090'.
    rv_data = rv_data && 'F337F908740E6FFBF58FBD61D454B351838E454A209519999E2E86ED7876A332AF7334075125EADF'.
    rv_data = rv_data && '756251A58F35DC07CA337ED4FCA2766DAB7E2543BD6D3C25A2C08B98BB5E51A4FA5B4E01A363FE2C'.
    rv_data = rv_data && '5E6E322810BBC84ED9AECA0F49538527640DAA7ABA59FF912543C9C2858BF2D8BA3BA610E332EEFD'.
    rv_data = rv_data && '922B951E8506'.
  ENDMETHOD.


  METHOD shell_recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914EF1C0411C93BDB480A2D95F2'.
    rv_data = rv_data && '787EB977000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '7273610000000301000100000181009353A3BFE8E17C8C711CC195C292D13BD470389E7FCA637450'.
    rv_data = rv_data && '6CCF9A9E85CAE703CA61DECD124220B86E07041FB03BBDD111E193909A43BADF5EAF2CDF8A38F60C'.
    rv_data = rv_data && 'C0E51952079850A1A02573B9452495E85B3654872583EEEA5E2EC5907C9FA59BD24B17C840C0D69A'.
    rv_data = rv_data && '3E77D0B236BBFA5A96CD7EEF3C989B08C749BB78DA59DFE945151B796D085C7FB10F3D44A7F2132A'.
    rv_data = rv_data && '2853F68F233359FF9770503224B2A6E4A44F323967F80BCFD579C05EED36CD3347246B058D6F9E73'.
    rv_data = rv_data && '975561806B8E9C25BFF28B4D6FBB7424B3BC6B66D1136B952A545E1CFC033D282F2669F5989BE97F'.
    rv_data = rv_data && '0F7E232AF819532380B4FE434B3D1B9AF02BB1AB435F1CE8EDECA938AF585F9E3C7994532AFE536D'.
    rv_data = rv_data && '9C6CBC4DE089928F6C947AACB8E15BE3CE8C8538E444F60B0132A449CD5188D123A69FD7C33577CA'.
    rv_data = rv_data && '8FD22232AF266E799B0DAB2B44C23F0ABE74517EE8BDF0E73F33A3D72AFF4B839D218CA7CB467286'.
    rv_data = rv_data && '2CB9E88A09312DDC0C7772E48FD8E701F222BA4DCFB8569A0109A460997E4E0BF8919B088FA8C500'.
    rv_data = rv_data && '00002085E574E1A0D1538D67D629F781090842DEEBC25F23D2E5AE50A166A4BD53C7230000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001804B4FC08B722C018DB783C20775AABDFCC782AD0F91'.
    rv_data = rv_data && '874F8A6855A3C74EB506781CB67E1F00B13C68BD2B106EEA104D867AD09E2AB7A363137941AA15CB'.
    rv_data = rv_data && 'A726CFA3DE6ED1F08065E43507458F48AB3A256006E66A36C6CF07828FFB16F4DBB0BB86E4B7F29C'.
    rv_data = rv_data && '41FDBE2EDB1E4F2F746226FB10D5B3FD29A673165B825D40F131B0121A033A129FB3E5FDEA0BCA12'.
    rv_data = rv_data && 'F2B507C060B55B40DA759AB2E4C3DFBFC56D2F070A2C60446BE5EA236D1385318F324A16662D3D38'.
    rv_data = rv_data && 'E86894D1151293B5FFD05D14BA896A253185359EAE76B7D88F2FE0708F148EA4209670A3BD294C66'.
    rv_data = rv_data && '20915CBB33AA1E5768FBC98F2567357E8A7576766AD28B377699EDDB8A37D6C799A16500B9B426F1'.
    rv_data = rv_data && 'DA2A3924128487843F40457F199E5B34B70F17F14D28299D00DEF1DB2A59D86010A113FD96653148'.
    rv_data = rv_data && 'BEDA50CB2F94B1D92EE2026BB90C7B06DBC37C2D6C3189003599CF803229DB0C9051A6764BDF71B0'.
    rv_data = rv_data && '8878BB51DBC3003A20429F8E6E073FCE22A3EFBAB0625A8051D08CA75B3AF30AED20A6CB712BD02D'.
    rv_data = rv_data && '40C69F00000000000000000000000000000C0A1500000000000000000000E159821D5ED28BFDC982'.
    rv_data = rv_data && '233AB9F6A8FFFFCD30BE20E688090D0F6F1C09935FA9DD650E409A7997C0CF2F2C5F6067603A496E'.
    rv_data = rv_data && '3D357298DB487A8973BD69C61BD2299A2A4B9BD652CC4BE518A0F85B2C278B5F48238DBE1DD12309'.
    rv_data = rv_data && '61FD67A43C0174FD84A67A321113B70CAD8F1518414A7E28C6252F93B813316919D856AF20D4A4AD'.
    rv_data = rv_data && 'F30A9722666605045F9C592A585BC955B3370BF7AF2051A539D3CEC2D24B74F4C8955E9B4122755E'.
    rv_data = rv_data && 'FA4B951A2CF3F74D57FD887037C3D456B1357808BEDEB6B8610550556B1D8354742A8860C2A80DB2'.
    rv_data = rv_data && '333834C54D0A0B8E73EE659EFEA231070B9F556041D4EE626AB4D220C3C2961A3047B5F405232ABA'.
    rv_data = rv_data && '818DEF48EC8E38EC06E4F685967EB595CFFDF896BA2AFF21939822C80FD69703B900BB85CF4E2C83'.
    rv_data = rv_data && '52978425117D9EA781821BE488A4AFA22E965A90DEA4A1519EC38598789D783F3A82DDB1BC8E478A'.
    rv_data = rv_data && '808C5A79AA426CB00EEBDE16E62E600A4FDD14D674F59CC27489D972CDCE5301B6876F0795724C6F'.
    rv_data = rv_data && '7581E74624F631C18FBA253571E88D522E8B5438B4D29CC9DBACEF4F5AE8F5A59125989EE12923C6'.
    rv_data = rv_data && '0B2F5252476C8F4D03F898580CB915479E7B86E7FA97DBA69CC99D79530FE27483A1CDC41E65EE5E'.
    rv_data = rv_data && 'C0A0D56440375C030A185E58C41A2E9D99C287400D111F40E345A74C934650B8C9863BE6E8E9F4D4'.
    rv_data = rv_data && '9388E6B599BA8C05036EC92EF3239512F4F8519D90D075A8527890E6A7748B8A8D5F04E61411B58A'.
    rv_data = rv_data && 'D8B2D47E80CF68AF7E650C708134A637A1C42967B0EADF7DC0E8DCAC2A4F80A75D83BFC0082A9D00'.
    rv_data = rv_data && 'D899BDAB46C9D5738348EC3A42D926C01A0F776367D46ED788035E294BA7DAD0E20097E3B00F6205'.
    rv_data = rv_data && '100398037B30CCEEC181ED5FC9D8B8C4EF711509F0F0F12D7C1422F3A8DF4F455E0CF30887B5860D'.
    rv_data = rv_data && 'C1796C14AE580A63C505B7D1A60DBB632A9E514C94BB0CCE286C264B8954C3B5F31144BD40B951AF'.
    rv_data = rv_data && 'FC7DA5AB7215F9679B98945F53E330EB7B2A1E80B3F4141BF408D14357F6FCBA34E66144922E1AD3'.
    rv_data = rv_data && '7C5B1FBA250113D18126F0D0A3539A24ECDFAC8EBF8F1379877079C6883311F457C97532125635F5'.
    rv_data = rv_data && 'EDCB6ED197737FA9E43CEBBF88EA889657B1C59FC91EB443710B01D349D9A4DBC92B23398C538DE4'.
    rv_data = rv_data && 'AF3E8F79CC630D96CF967EB0A643DB6128F48D5E6FD9DB9DB17CD3B9A326DE7687739D719D8C6765'.
    rv_data = rv_data && '5E760AA5AA606BEE5718A7E72E8A19DF1808DE61BFC70F6312CCEF1AE138884F752A895D27A154F9'.
    rv_data = rv_data && '236ED27B8124AF05E0F0D5D8D0A299DBC5EA775476137380AA1BD977F040EE0486E30D1D31F788FD'.
    rv_data = rv_data && '505A041E4953B88E6954DD1A244EF50A68E6DF6ED424EBAD5CFCF04990E17B735241D36F29AA5419'.
    rv_data = rv_data && 'F36F36A72321497685B64545EAEE14C4BE608F1C4CBF949365451179ED14036840356638E51251EB'.
    rv_data = rv_data && '034365F4490C8721CBFE7E3B93C9B2B85FF8BC0CEE3BE03F786A44F33D17EB21FE5A524ECB214B04'.
    rv_data = rv_data && '093DB3A83841DF07BC1FB100C208135321340700749A018AC3D0D8D9ED90D73F1735BB43F063FDD7'.
    rv_data = rv_data && 'E37A638D8B114459A44CBA7583AF5F1A1D30D929255E06CC880A8F643395558D0E87706921108185'.
    rv_data = rv_data && 'DFA910C0AC59687EB8A9B82449CED02FDCBC9FBDAD08DCD1DDD96179F6A96F230307D533FDE8AC9E'.
    rv_data = rv_data && '24DE1CD263B0D5CD26FBB8A5B0262CA1C9666692C30F5B19C4AD2F3F0DCAA5359E8233BAC847ADC8'.
    rv_data = rv_data && '996E6789E9FF57FBA0A29D321B6B3578A347FDDC0A35925D423C80555A20BCF7216902D05C22257D'.
    rv_data = rv_data && '8B1BB3E5D1F2DBFEE7A867126514A6200EBA4F0DA4A2A8F8C2A92CF3D1DC1B2146C5C208B814B4A8'.
    rv_data = rv_data && '5A0CE0B0DA52649D55997E00ABD33B65BE4443C2AB157105259D67CCA1B5E6D248D8AB64238E09A2'.
    rv_data = rv_data && '0C918BD6D6DC8FBE38B633EFE6906E52A988D63A1992BBF6FB002FD461318A9F79C74CD9C30B8924'.
    rv_data = rv_data && 'A545FC9817AD39E7A72D9063FDDFE5465EEE72D21798B93669DD7206BE27FA80A0009B17862204FC'.
    rv_data = rv_data && '388DC74826757DA4166621FB9776B2AA338E873C7D8518389596E0367CA5BE11A2E9C1E749EA29E4'.
    rv_data = rv_data && 'C78C99DC6842746D01C9645DB23D19C4E5C495F7CDCE2FCE0749486A6C26604BBEE3893C2F40BE9B'.
    rv_data = rv_data && 'A21B11E59D26F81E4A520125BBE8D3AD1D885F433E0B3CC68B2168777FA095A8657DFA00B7284ECC'.
    rv_data = rv_data && '7C1D1980C4CA53B20D94DC86D831214D228F7E119D88828E6A30C28B66D5843544D66D14240A5B9A'.
    rv_data = rv_data && 'B1E7677A26CF680EBB2A8B6BD997BA272D3C5033BAC1121A606315B209412B77DBF73B31A396A4C7'.
    rv_data = rv_data && '9E13E6ADF10286266A88A85F509CEFE36EF33FC9C58FE1EE454DB773C9765B651FEB9B2425B91BCE'.
    rv_data = rv_data && '43FE9FEE6051A85496FBA8094331'.
  ENDMETHOD.


  METHOD shell_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABABF3680FE67AAD27319CC671AF6FC8A1A8F100'.
    rv_data = rv_data && 'B2E30BB5880A07F718B7C56B6C5E675F5161C08428E7BB6A392B4FDB2A9B1A8A9DDE8CFA54E9CECE'.
    rv_data = rv_data && '8FBB388B1DF1D07D8F0ED4AA5EDA48E162441F3CDB18EF22D9B7E4EFCF5407648B69213053651DC0'.
    rv_data = rv_data && 'DEDEBE4C45244E571C17381569D857FB920F0F2D78D3A90D2471C3246763A17492A46FD0EB70FEFB'.
    rv_data = rv_data && '7791406CE8C5EBD56286DB24AB0CEF659B7B8933A6D32E1C44331DC2076F364F87110CEF2A08C675'.
    rv_data = rv_data && '6A516B91153947C32661723121954C6A47CB5F6124B60CB6B03397135BB8F16EEB27BB0A75C661F6'.
    rv_data = rv_data && '6703BE07B58369559B24D07B893B520EDDE77F12BE687D2A86678997C20E5892FA7B2AF2CA33874F'.
    rv_data = rv_data && '029B8DE020BE51B40F4696D8A4F0426D2F5406C870C435BCED548EA14F0E4F0D3E9E6305F876F06C'.
    rv_data = rv_data && 'EF5886B99F25F72EC33EC11E855381CA98DCAD4B8EF14A9A99177B34C30E5CA75E718A28B1A0CC65'.
    rv_data = rv_data && '4F7125B7D2683792202B8D7968D0999D4295B744A808CF89E0BED1688388E50AA298538088C7B856'.
    rv_data = rv_data && '464E918E48581C1F54A98D4706E6D3DD241E629AA3F05153EABEE2E4556CC729C6D3B90CD6DB66E1'.
    rv_data = rv_data && 'A5D126033A463A479B8F52725E7F5DB3494440B790D38CE201074656814F4FF8A5EEAE2EB370B39C'.
    rv_data = rv_data && '347679CB04DE14FB080C5F11726A5902F1011F9AE8350343C4B84301D6E51CFDC0660349AD4487E9'.
    rv_data = rv_data && '5EE6AFFC9DBA34C717905F4ABB0AA7CB6F0C40A8943F53A661A4A79DDA66291FCB4F906A81220624'.
    rv_data = rv_data && 'B0A9989097E5AD51A2B0C6F39842879763E89630D940653262EBB6A366B8492F912E4F6B8CE53CD3'.
    rv_data = rv_data && '9A3F5D56603E32C2ECA759AC7042'.
  ENDMETHOD.


  METHOD sftp_session_recorded_session.
* Captured from the pinned OpenSSH 10.3 container with fixed AB randomness.
* One connection runs list + download + stat + rename + rename over a single
* SFTP session. The mock hands each phase its inbound in turn, mirroring the
* interactive request/response cadence, and the single accumulated outbound
* is verified byte-exact at the end.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lt_names TYPE zcl_oassh_sftp=>ty_names.
    DATA lv_data TYPE xstring.
    DATA ls_attrs TYPE zcl_oassh_sftp=>ty_attrs.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->send_version( ).

    lo_mock->set_replay( session_recorded_open( ) ).
    lo_ssh->sftp_open( ).

    lo_mock->set_replay( session_recorded_list( ) ).
    lt_names = lo_ssh->sftp_list( '/config/oassh-list' ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( lt_names )
      exp = 4 ).
    READ TABLE lt_names WITH KEY filename = '612E62696E' TRANSPORTING NO FIELDS.
    cl_abap_unit_assert=>assert_subrc( ).

    lo_mock->set_replay( session_recorded_download( ) ).
    lv_data = lo_ssh->sftp_download( '/config/oassh-list/a.bin' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_data
      exp = '61' ).

    lo_mock->set_replay( session_recorded_stat( ) ).
    ls_attrs = lo_ssh->sftp_stat( '/config/oassh-list/a.bin' ).
    cl_abap_unit_assert=>assert_true( ls_attrs-has_size ).

    lo_mock->set_replay( session_recorded_rename1( ) ).
    lo_ssh->sftp_rename(
      iv_old_path = '/config/oassh-session/source.bin'
      iv_new_path = '/config/oassh-session/renamed.bin' ).

    lo_mock->set_replay( session_recorded_rename2( ) ).
    lo_ssh->sftp_rename(
      iv_old_path = '/config/oassh-session/renamed.bin'
      iv_new_path = '/config/oassh-session/source.bin' ).

    lo_mock->set_replay( session_recorded_close( ) ).
    lo_ssh->sftp_close( ).

    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = session_recorded_outbound( ) ).
    lo_ssh->close( ).
  ENDMETHOD.


  METHOD session_recorded_open.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A000002740814BFEA8A542469DDCF37F16084'.
    rv_data = rv_data && '16A8877500000039637572766532353531392D7368613235362C6578742D696E666F2D732C6B6578'.
    rv_data = rv_data && '2D7374726963742D732D763030406F70656E7373682E636F6D0000000C7273612D736861322D3235'.
    rv_data = rv_data && '360000000A6165733132382D6374720000000A6165733132382D637472000000D5756D61632D3634'.
    rv_data = rv_data && '2D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F70656E7373682E636F'.
    rv_data = rv_data && '6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C686D61632D736861'.
    rv_data = rv_data && '322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65746D406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D313238406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D3531322C686D61'.
    rv_data = rv_data && '632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D31'.
    rv_data = rv_data && '32382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D3634406F70656E737368'.
    rv_data = rv_data && '2E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C'.
    rv_data = rv_data && '686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A6C6962406F7065'.
    rv_data = rv_data && '6E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D00000000000000'.
    rv_data = rv_data && '0000000000000000000000000000000003640B1F00000197000000077373682D7273610000000301'.
    rv_data = rv_data && '00010000018100AF07297A07CA360A752FA941B533B1980E28F38D4F55A32A8D0A56E8A9669F7D20'.
    rv_data = rv_data && '6C67F87AD3B0DCB20DB620779C9AAA0B22F2B49840A069BCA46D017DAFC8B33A212C80A133E90210'.
    rv_data = rv_data && '510DF8BFF9069D352AF924AB8E429C29E3D9F6B56F9CD27DC89A02DE62EAF5CDA132E195713CDAF4'.
    rv_data = rv_data && '6E04866CC031BA404CF605B9331DF04BBF9709BC5EFC224D5DC72B65CDD6ECA5FEFC8C771B70C7A1'.
    rv_data = rv_data && 'D77D0BE8C3FFCE350E82A07399E4A84DFDC81269D2215556D3AA07A4160094999F7DDE5D6DA3CC46'.
    rv_data = rv_data && 'AE2443F53E7FF70E1C1AA93014A37505F8B51C7444EA9E82ADFBF43543B74DAAD3956186DB181FB1'.
    rv_data = rv_data && 'F650105BC42A6B73FB469A12B3DC74C448921B5CB58FA814F90807823D7691FF4F2E8E9522630B28'.
    rv_data = rv_data && '669F6F5EE3006C51BF5A4DB9A3C2B7D1D28982DA55DB72B5D581EE8CF399EDE6334DD6BD96252E5C'.
    rv_data = rv_data && 'FB40B1BAFFC972E190EFF0748B0344E73EFEF8274199F45DFBFD103F7F87751ADA5251F7AEFF1E34'.
    rv_data = rv_data && 'D3330776226BDCB4BB6A663BCE4F20B9E068F7AAA2ADF7B81756BE98B0E633000000209F2E14F0EB'.
    rv_data = rv_data && 'EC580F5C7D7879DBCE173A65B51448E0F241ED9DB3C55B6EDBD407000001940000000C7273612D73'.
    rv_data = rv_data && '6861322D32353600000180352493F130493A1B150C1176E1760B02B93693794342BB778101D9BEE6'.
    rv_data = rv_data && '1163E327F36357F23F8F4958A0C5CD99FAA8D1C67CE28F7CA54B16DBEF80F3899919F8E833E2A817'.
    rv_data = rv_data && 'F127A0C604465F41B06F557A05010101942C853D14DE38F6945DAB2B771F2A91C62462D7D5D36463'.
    rv_data = rv_data && '8DB50070B24786FE546153AE679F1181F26B3EB3DA9B48B09A208BCB35356A33CDF497D00FF9F2F3'.
    rv_data = rv_data && '487F683BD1E88C8DDD5085115540F0AEAAF2565CD9D0718FECD058A717E8D1E1100DBFF3DDE88CF5'.
    rv_data = rv_data && 'F31D0ED23C59579BE73313C46D256D3808BF8475C6497C0CBC720C7CD6230CD4D91347D1F5A0568A'.
    rv_data = rv_data && '752540BB06606450A163291A9BC3FDC9E066DB3F973CD676BC7547294F1DBCAD1A6222DA25EBFFE1'.
    rv_data = rv_data && '97C7AB168AAF9735540BF63D699C4F7816A4C0BCDC6EE0D6B835098224BD1CED0FD90B8B0A70BCA1'.
    rv_data = rv_data && 'F4B96DB25C7B0F423500B0AFBD9629A912178B04D39E065BD2CB142E070BCD683DE03A8471D733B9'.
    rv_data = rv_data && '2481E474AA02527F8433570463B7F3AE516B03AE0C742EDAFE4ADBA74C09C26AFF015E0000000000'.
    rv_data = rv_data && '0000000000000000000C0A15000000000000000000004227624962D419BC548CBF9BFD53CBC26B84'.
    rv_data = rv_data && 'ACB75C9F20D6D62A034A3EF66D75856A728F10B6E467B763EDB2BB873D5156456558BD11E7F78C76'.
    rv_data = rv_data && '306A5CB102EC53DD6E3D6B9ACBB48AFD7A565D5197AA7EFF3D2C899F6FFDF96DC4FC14C063D1A9A9'.
    rv_data = rv_data && '9525B1CCEAEB3F4EF99C5131BDC915FA0A2AC9B49AFAA5264C734A526982CF0EFA990761429CDA9A'.
    rv_data = rv_data && '2927659913EAA2AF660B48825F59FB6136905B870EC1065525452BE624220634E3C87E9A682BB07C'.
    rv_data = rv_data && '4C74240FC2530CC06B9A92FAD66ADEEC613A3356E46594F2654838FD0E057334C985DDEEEEFFB346'.
    rv_data = rv_data && '7CECDDF5035763C7A0707695F2789FDEA82AC93F28883F35F4D1A0CD076461EB6D65EB8A37E8619D'.
    rv_data = rv_data && '255D0BA89ACE6EBF7533779B12ECE60A2E2A125EDB7A24BF66BC47B860C7F1D536BBC91A20022B1E'.
    rv_data = rv_data && '837A265E6498075B9BA86641F97C3F3134B061351455F0EDEE0CE3EB9B1B00A81DA771171D58FBD9'.
    rv_data = rv_data && '33F8063A5178D5FD0FCD1AB13D69EDD9FCF3761245548EB99D0F43A862297F343E37A6B6A2D11174'.
    rv_data = rv_data && 'A6048849A5C93DEA07BB1CFFD0B49C042A2562F0FADCFE08BFF3D8E720F29B8D36BB22DDA5398979'.
    rv_data = rv_data && '82B101A4D5C2E5D2F34567E88C61BE7686717142CE8283BE08F3CB60FA5B7D8FEBE11B5052AB4F5A'.
    rv_data = rv_data && 'F3AA05FBCE7046A33F738E0ACB46262ED0BD819F33A8E4C244B3AB5DE68B4E2E8369339EB62E8F7A'.
    rv_data = rv_data && '4A28F9E98E7E30EE330F4FD44CE6A24C374D19F367707F61F0625BB16E473D5BE508AAFF3B744C13'.
    rv_data = rv_data && '94AFDD11074DE2D58A4E81EF0E6C90050786EC52ABF8833A4FEC91797203C8AA78344F0B39AA19AE'.
    rv_data = rv_data && '8EB36713D8E9325F475F5F8EBB48097912F94315F9B030A6612F1D382B6E1B83E76802B2A701AA55'.
    rv_data = rv_data && 'EDCE6678237195640C04F84599C049544E63D06ABC202E792F05DA7AB410E912D48862277C0D13B2'.
    rv_data = rv_data && 'E765AF8EEFC7CE4865F0D778E2CFB3D00C7A88B96317407E10106A0AE34DF1F8D6B1A8A67D8A2E57'.
    rv_data = rv_data && 'ED02E0763D49C45D50303496DE5F1EC562E0608912C344E3AEF8786984F982ECA4587779D6D935F8'.
    rv_data = rv_data && '9E1F3E43DDB484B8EBE3954A0EDA87AC7039CF8609CF8B49722F09DF4D19D3AA11E365911674D5D3'.
    rv_data = rv_data && '662DE76C685CDA3F97110754FE61BE2F8AE1969D4DAD2596F3184A021FEEC4FB0CF8EE60FFA3DF2B'.
    rv_data = rv_data && 'EF22D0A970908E84A2B6202C0B08E7652FF0C2A89E36442C341F2CC283EE8231172550B6CDD11997'.
    rv_data = rv_data && '9086422FEC0E9F46D22AE75C5969AE0E2C41F3B5221C387A734701E0DC953BC5745877DE3894FFEA'.
    rv_data = rv_data && '349A802A8869B7095C1E9C2DE52C7A7D0B6654C3DDAAF6531CA7CCEB7162A0EE3D2FA434CE9E7A51'.
    rv_data = rv_data && 'BF91F617F6928E83ABEDA39042054E98BDF7CC4E5FF6D4132CFA556F4C49625495C444BF556A0B62'.
    rv_data = rv_data && '89CAC2D90F85CF7ACB32973ECC15B04675155161ECC5E584A48CF1B7A6E802CE7B88DD747CC95F79'.
    rv_data = rv_data && '4692E7EF778BA7053B7F67C593D4240A14E903884DAECDBECC22FD248E506B1B7B3B323FFA7EC0C2'.
    rv_data = rv_data && 'DF1A1EC227B15015467EEF2BFA76030654BD3431FB3E092E02BC391F2C3DC8BD76BBBDE9AE44E8A8'.
    rv_data = rv_data && '0D0B545DE8C60001B6B309F050AFF5AD4F282A31DD7725ECE27EDAB7D801E5ECED19F297CBAE1A88'.
    rv_data = rv_data && '56B2CF4874170D40B7501B4C714BFFAB3B6C2527814E058C7413AD290DAC59DF571EA4D5AC46DCA7'.
    rv_data = rv_data && 'DBB2EC89CBD14B42B03E42A9794430B18EF357B873B6F56F135D9B1FAAF16ECC9E9416E95D537CBF'.
    rv_data = rv_data && '7C1CD9DC3BDE2F28E928942330F407DAF15EF7333FA11A303C0760F3F318DB829EB6CA910483488C'.
    rv_data = rv_data && 'E2E2E42C2C8AB3F6F756DBB56BCAE3877217944908C22B2E21A9A3D60F288D9F63ACFBC6588C05DA'.
    rv_data = rv_data && 'A90E9B32B413550379F3D27E73EF94C930E7019E1CEEF38A81B91FF2FAF6'.
  ENDMETHOD.


  METHOD session_recorded_list.
    rv_data = rv_data && 'DBCDE4B71F7D4CBF2CBA53F753CEEA0C68F00E852D93B201051B1B5ADBE48B9A7E24B9D227B996E6'.
    rv_data = rv_data && '36BE9B71F46F385B765944741E26C8815BD6C235C59E1FF3ED2ADC67F1BF155054CA5347F777B831'.
    rv_data = rv_data && 'A4E8FD421F2445B2B854ED6EE60942AD1DF783BA69DC879248783A8ED541B61EB27B97E48D3FE8B5'.
    rv_data = rv_data && 'DF3580C619A7ACF17CF539894630218B4FDDD39581A0570D3D81A0274A3FCF06CAA514248EDCBC51'.
    rv_data = rv_data && '63F25EC19D5D4C5CEC41B824539AFDCF255B43A84F0E2478F7E7E4FA9C3C96C904875AF00419592C'.
    rv_data = rv_data && 'A18A4AE6469D65BD35333CE2FD43CF749903BDED6F61625DB336D96549185C5F2DE88890F7A52990'.
    rv_data = rv_data && '11A5CEBDAB6E417A260466058F6A517D893C86055CC33C3164C442A1EEE24D69620E5012D559B550'.
    rv_data = rv_data && 'BD3D27BEBFAA4F25D10873B1EC9C082B41E312CEEBF151FF59D10591B93685A624F6D86D345BB934'.
    rv_data = rv_data && '58C520A476D02984B2A3D5ADD7245FC7D079E60E358E33C9650BC2FD88860CB12B4EBE954EF9BF57'.
    rv_data = rv_data && 'A128A7BA5EE1970300BAB58460746A0A673B8224A965EE8AF62FD449BAF671E48598C97D8F81606D'.
    rv_data = rv_data && '4107BFA933754F7B12CD4EF1052D0099FDD030CBB50A2165495F6D5756A9D42B3C1483FAC7A8AA28'.
    rv_data = rv_data && '9E033118C689D7395FFA34903494D2C4C61180A267C345D0C95478ACABE58BAB34A5D11D937B097E'.
    rv_data = rv_data && 'F85324339F56487F1AD3A0CB00F26C23A0B686117915710E31B877164A02E71DBDBA03A7B705FA0F'.
    rv_data = rv_data && '6361FEE3DEF396915832666F6BC22601712E6F1B607C3A2B999B21CE4E4D7D8521CFCDE4934E0763'.
    rv_data = rv_data && 'EEE5D6E7152C2E84B25E756252F24DDFD4BCDE8F9542305C7F6B31095A3744558D92D409D2A82A68'.
    rv_data = rv_data && '6EBACDA2F7B1C6957121F1EE2B8C49F3FBD3C1EB606E5FF8025D61CAB9752F8047031E9F1B2D152C'.
    rv_data = rv_data && '5EB94304FDAA7AFD44124532E4BC89209D6C129FB562A4665216FACAF741958148A2B7B4E8519131'.
    rv_data = rv_data && 'FD9E9F065DE5F5AD5A7682C8AB91DFEA57A0C6C57F7B0D7055B09B37268D3526675E86E1AEF123FA'.
    rv_data = rv_data && 'DC7767E43D02620661BDCCEBA39EF5CF'.
  ENDMETHOD.


  METHOD session_recorded_download.
    rv_data = rv_data && '62B7A80FFC204BAE185BCF8C12640687F853144F46077F018E916ABF310266870FC17015E9D42F5C'.
    rv_data = rv_data && '2EFB415116CCB2BA5360A4633093B204574E9FFA0830967CF4CB80925D0DF5BA3D1B35554FC08645'.
    rv_data = rv_data && 'A6C0FB70952402270CFF3CEE0B89B8FB606ECA0276F84E9A8C35A30A5581C9B027AB82295FAB337A'.
    rv_data = rv_data && '06FD0299A5BFE789A458420C4D6A3DCC418BE034155E470DCF1CE66B5FF9A74427F6475189E7052F'.
    rv_data = rv_data && '06E49A8B9C7343DC66FF29BE19F438257BBAE4E7048AFC0F485F24D458CC7C1D501891B0EEC74C6D'.
    rv_data = rv_data && '278C76A3B2F83F853A9357A41A47776645B90DEF29BE4F33176A85D77DD3188BDE498310D8E5D2BC'.
    rv_data = rv_data && '7A987FFB51F1F566978FA5BF447D946B9783A9DBE59553595327340AFB3930792F642F5280AEA232'.
    rv_data = rv_data && '727B7D0C9D3C96C55F52943D2F017EEE47874953A27FD0631B87DB244881B5ACFF4EE52B555879CC'.
  ENDMETHOD.


  METHOD session_recorded_stat.
    rv_data = rv_data && '11E2700E97CFDBD3F85FEE960857C5F34C85DC82D72B474C855B3A5CF3A77E472502DE1EFE9AC367'.
    rv_data = rv_data && 'B02C23D6E03B92D5E7F2867478A641D9ADDE2C19022D78731BE4D414605FC893E85B084D463EA60E'.
    rv_data = rv_data && '1DB3F0291B4EB48CDD9C094619BD574C'.
  ENDMETHOD.


  METHOD session_recorded_rename1.
    rv_data = rv_data && '8C1E90D3D7A514BA38F0A90BE86697B50B08E3F75BA5D3911C0E0D1EAA3DD1A290D4E133EF9738FA'.
    rv_data = rv_data && 'F203BF783056BB2D9199A921170AE1EBD7CD6C587AB0266B6869B65EA34EDDF92229E27D0FBA49B6'.
  ENDMETHOD.


  METHOD session_recorded_rename2.
    rv_data = rv_data && '5C1549C35C7D58AD840440EB40A9B7D08983320BE3EACB6146662F2079329000A50F0E446BAC850F'.
    rv_data = rv_data && '94A0A122A177507637BBC49260C95294E3B06D6D75EAEE4433E0F9A5062B716013FD7CD5835B30E7'.
  ENDMETHOD.


  METHOD session_recorded_close.
    rv_data = rv_data && '873003136FC51112AC273D86C04A457C8DAA33101BF3EE736E9A56BC2115A111BDDC8891CC0FE0EC'.
    rv_data = rv_data && '0C8A72A2823D438ED2D94BBD8F5838A5FE4A36BDB0234B12652A44520B26E08326E72C7E8EFF3096'.
    rv_data = rv_data && 'EB1B3F1652020AC171343BE9A8CCC4C11F127B0A1ED5E8E4DEE1945909CCB4CB269D3AB6F95917CE'.
    rv_data = rv_data && 'D0FDDEC9617A1DE7'.
  ENDMETHOD.


  METHOD session_recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000012C0A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D000000187273612D736861322D3235362C7373682D65643235353139000000'.
    rv_data = rv_data && '286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F'.
    rv_data = rv_data && '6D000000286165733132382D6374722C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D0000000D686D61632D736861322D3235360000000D686D61632D736861322D32353600'.
    rv_data = rv_data && '0000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABABABABABABABAB0000'.
    rv_data = rv_data && '002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859'.
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABAB860C058AB621F5EECFF6E44048EEB59272AF'.
    rv_data = rv_data && '0128791C494F921716EB32BC9DC1B0A90C4D8B4AD1E45AE09160BF0B6D0384FB784E03F636543EC5'.
    rv_data = rv_data && '7ECC29378A8E5F3B6F16FD1174A42B3D5A2B778639504041136D2B8BA2B315C790A0B0047DA6B0BD'.
    rv_data = rv_data && '79D439E0540662D66783988192375F2AE7ED00D0767951ED61509053E04B0BD02B835236243A6694'.
    rv_data = rv_data && 'F592AB5A3DCE4EAAE43740109C77E43E6E23231EF8A002C06DC7C4C9FE71CF0A7B9905C258F7E067'.
    rv_data = rv_data && '4B61A2ECAABD0D9383507AE6B16C3C3E5ACAD8ECAD9EBD0F0828316025133FD1E76707823F0680DC'.
    rv_data = rv_data && '5DB1AA75ED14558722621547B7936FD3EE2AFF9C7A79602315A4A9BCF79DCCA71EEB6DDBF9738E77'.
    rv_data = rv_data && '538E4C1CF9ECF2136F8C8C63384D690CE5CA1395B12C6F345432EC84CCDBF9EE681C7CD2F368231D'.
    rv_data = rv_data && '1702E4F17129D1E7A130EE96339EF686FD4EC10E360EF2946B9C5D01133D1AE751283F978A7DDABF'.
    rv_data = rv_data && 'FCACFE61864089106896E04CFC784943DA14855C4601280E011F8235FC5BE24993FB3CB830AA0632'.
    rv_data = rv_data && '3570399F1C1EEFA2F93A4A861BF8D79774C001E698752AEFE819CE1FDE87768A70CB66B63F4F8476'.
    rv_data = rv_data && '78F8649F320D723CD2AF051A0912089D9EE0BDF91B6810D5DF535132C468CE5FF940D2AB1F0D09F4'.
    rv_data = rv_data && 'C0D56DC54338554B73AD6993904F017FACD562BAF01A7172925A348E4098C20CE73EB04EB44F35C8'.
    rv_data = rv_data && '1F17FC08528155107AF10226EB4F7C88A278C5669A5A3DB06BAFDA684172D5BCDFF9D7650F37DE1E'.
    rv_data = rv_data && '2B278381BAE69FAFD14071EA00F1E0890D18C042613820A7B4C8400B7213E42B4A1941F5D7E3A827'.
    rv_data = rv_data && '10CF30181520974D0DF3A3BAFA9079BD79D0116F863F83539F9DB2888158D350D78E0A007E26F044'.
    rv_data = rv_data && '2139F5ED4DA35171AC7730BDF50DC0714936C5A200967D1D3BB854278417096154308EFF7EF84FE8'.
    rv_data = rv_data && 'AFA761FBE16FF29D1BFD09EBDCB6E537239E7F902EA24F85F34645018944C04AFF4039DD25F7BA3D'.
    rv_data = rv_data && 'EC371948CBDF1CC9D361B5180AFEC1FFB221DE95A37A0DE5F6AE53B2CB1C0EE2D49A49F4E68358D6'.
    rv_data = rv_data && 'FE834A4B5F4A7EDF54A9F609BCF1E00B6F53EEF8669334E4F14008144C8FDFE713A9F15663C04C1D'.
    rv_data = rv_data && 'BB2BE589438816898F3B12FF6A2BE2BB1FE2AEEA5EA3F71B959C5C31396DB85A195A9930DE141665'.
    rv_data = rv_data && '6F8EC073E51FD0B175F55F6ED17898AC5C5B32E003AA9337A84F4AEB9BED6B113C9EFD03E83510CD'.
    rv_data = rv_data && '87EDF39F98CB433D6CE59639A46F1BA69C7A2D354C99CD3105B8F365D2A742164516682856A91D6A'.
    rv_data = rv_data && '35DA6D42E981678C033E7669551AA82C84C760EDB045CE002989F34252D0BBA95635C80348302C3D'.
    rv_data = rv_data && '79668B45D086CA8032772DB472E905C0162D0E9E06EA75E2171594E203AA3CD9A501B17838EC3012'.
    rv_data = rv_data && 'B786600ED6C929188DF316989DA02A61C70D0C391A6021C461B826B3985D176D493DA4D087F43328'.
    rv_data = rv_data && 'A4DA918179A7178589C7BF34E44865625C630810F8BC6C681C7DA3DB5530266F6F09CCEFD0CCEDBF'.
    rv_data = rv_data && '0019BDB89FC4C84A2F19CF0A9E7BFFF795C7B19865F2AC9055462E12D8FCD6E3FBC36BE0521FCFE0'.
    rv_data = rv_data && 'E55643EF1741C231CD10E1D7C2A091575DC80C5CC3A89B8FB959C14D91A0AE07D8C898E602A26EC3'.
    rv_data = rv_data && '203CEAAF47B072A53BBDA4FD299C5942D73EAF3CCCE5C2B8AB89B072CA96AB2F467B0D0A8FFBDB5C'.
    rv_data = rv_data && '0BD9E827384E727B8890830E2B62AEF7FEA4D416ABC4D3A83D9A6601D5D685A43E5D3F5ED05D773A'.
    rv_data = rv_data && 'C2C6C18EBBD04F8CF376495B3E0685CF6C53700EADD81DA98A655A8B95C7F08BABBA8193386081FC'.
    rv_data = rv_data && '14113F62BD82B96754455BCD80CBF64C3A769236CDCF45DF13296CEB46C355219FC3444126D76774'.
    rv_data = rv_data && 'A77995981D5912A97FE263708CC0EDEAE1BEA7822497769EBA791A0CC91BF69A2441E4108CA4C64B'.
    rv_data = rv_data && '2F51F4E531F18DBDDBF40D01CB85723FF23AE9647E58558D3A1CBC2CA07B47A2D3FA74CCE5CE9BAE'.
    rv_data = rv_data && '6891DB549C0420815648277574814A98B18970FF4A61286B21CE1D6365A2F5772392FD4C3B6DAB02'.
    rv_data = rv_data && 'F577F6A07342132D5F4A14C5923A36114FB579C8B0F281236CD3EB327A41F0681F04970D62B1BB22'.
    rv_data = rv_data && '2DA1D191A3B34EB31377A8482385DE3E911C26AE65CE83663479A6A409F3'.
  ENDMETHOD.

ENDCLASS.
