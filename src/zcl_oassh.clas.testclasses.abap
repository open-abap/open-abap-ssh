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
    METHODS on_open_sends_version FOR TESTING RAISING cx_static_check.
    METHODS server_version_starts_kex FOR TESTING RAISING cx_static_check.
    METHODS identification_validation FOR TESTING RAISING cx_static_check.
    METHODS fragmented_kex_header FOR TESTING RAISING cx_static_check.
    METHODS execute_returns_result FOR TESTING RAISING cx_static_check.
    METHODS global_request FOR TESTING RAISING cx_static_check.
    METHODS server_channel_open FOR TESTING RAISING cx_static_check.
    METHODS transport_messages FOR TESTING RAISING cx_static_check.
    METHODS disconnect_stops_processing FOR TESTING RAISING cx_static_check.
    METHODS encrypted_message_recognition FOR TESTING RAISING cx_static_check.
    METHODS plain_unknown_unimplemented FOR TESTING RAISING cx_static_check.
    METHODS execute_timeout FOR TESTING RAISING cx_static_check.
    METHODS sftp_api_state FOR TESTING RAISING cx_static_check.
    METHODS empty_command_state FOR TESTING RAISING cx_static_check.
    METHODS execute_early_failure FOR TESTING RAISING cx_static_check.
    METHODS utf8_credentials FOR TESTING RAISING cx_static_check.
    METHODS recorded_session FOR TESTING RAISING cx_static_check.
    METHODS sftp_recorded_session FOR TESTING RAISING cx_static_check.
    METHODS recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS sftp_recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS build_ssh RETURNING VALUE(ro_ssh) TYPE REF TO zcl_oassh.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

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
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-malformed_packet ).
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
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->execute(
          iv_command         = 'echo hi'
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-timeout ).

    lo_ssh = build_ssh( ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute(
          iv_command         = 'echo hi'
          iv_timeout_seconds = 0 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-timeout ).
  ENDMETHOD.


  METHOD server_channel_open.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->reject_channel_open(
        '5A0000000773657373696F6E000000070020000000008000' )
      exp = '5C00000007000000010000000000000000' ).

* The common fields are mandatory even though type-specific data is ignored.
    TRY.
        lo_ssh->reject_channel_open( '5A0000000773657373696F6E00000007' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
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
      iv_user          = 'test'
      iv_password      = 'test' ).
    lo_packet = NEW #( li_random ).
    lv_disconnect_wire = lo_packet->encode( '010000000B00000004676F6E6500000000' ).
    lv_trailing_wire = lo_packet->encode( '0200000000' ).
    li_socket->connect( ).
    lo_ssh->mo_stream->append( lv_disconnect_wire && lv_trailing_wire ).

    lo_ssh->process_kex( ).

    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_disconnect_reason( )
      exp = zcl_oassh_message_1=>c_reason-by_application ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = xstrlen( lv_trailing_wire ) ).
* A callback already queued by the adapter must also be rejected after close.
    lo_ssh->zif_oassh_socket_handler~on_message( 'AA' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get_length( )
      exp = xstrlen( lv_trailing_wire ) ).
  ENDMETHOD.


  METHOD empty_command_state.
* RFC 4254 section 6.5 encodes the command as an unrestricted SSH string.
* Its empty value must not be confused with "execute was never called".
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->execute(
          iv_command         = ''
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-timeout ).
    cl_abap_unit_assert=>assert_true( lo_ssh->mv_operation_started ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->mv_command ).

* A second call must still be rejected even though the first command text was
* empty. This API owns a single session channel and is intentionally one-shot.
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute( 'second' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-channel_failed ).
  ENDMETHOD.


  METHOD execute_early_failure.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
* APC can report an error before authentication/channel establishment.
    lo_ssh->zif_oassh_socket_handler~on_error( ).
    TRY.
        lo_ssh->execute( 'echo hi' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-channel_failed ).

* A clean TCP close is equally terminal when no SSH channel was completed.
    lo_ssh = build_ssh( ).
    lo_ssh->zif_oassh_socket_handler~on_close( ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute( 'echo hi' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-channel_failed ).
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
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).
    lo_mock->simulate_open( ).
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


  METHOD sftp_api_state.
* SFTP shares the one-operation contract and validates timeout before channel
* setup, while retaining binary output as xstring at the API boundary.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->sftp_download(
          iv_path            = '/missing'
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-timeout ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mv_operation
      exp = zcl_oassh=>gc_operation-sftp_download ).
    CLEAR lv_reason.
    TRY.
        lo_ssh->execute( 'second operation' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-channel_failed ).
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
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).
    lo_mock->simulate_open( ).
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

  METHOD on_open_sends_version.

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
        iv_user          = 'test'
        iv_password      = 'test'.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

    lo_mock->simulate_open( ).

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
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).
    lo_mock->simulate_open( ).
    lv_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ).
    lv_version = '6C6567616C207365727665722062616E6E65720D0A' &&
      lv_version && zcl_oassh_ascii=>c_cr_lf.
    CONCATENATE lv_version lv_trailing INTO lv_version IN BYTE MODE.
    lo_mock->simulate_message( lv_version ).
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
    DATA lv_reason TYPE i.
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
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).

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
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).

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
          lv_reason = lx_error->get_reason( ).
      ENDTRY.
      cl_abap_unit_assert=>assert_equals(
        act = lv_reason
        exp = zcx_oassh_error=>c_reason-malformed_packet ).
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
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-packet_too_large ).

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
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C09146B3CBEA29D7DE0BA29DC880F'.
    rv_data = rv_data && 'BDD66A73000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
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
    rv_data = rv_data && '727361000000030100010000018100D14FEF59327175687384CFD6A1BCC7D05BBD50B29A86535E08'.
    rv_data = rv_data && 'A34250E2960811BF33955BDEB1ED1342A21F8D4056EB0A376C066B2DC239301E784BC5A21115067F'.
    rv_data = rv_data && '41246BEC95B39D10A99228E22FCAC86A5D52658CFFB5E71155850FD6CD273995671468CDB4A06529'.
    rv_data = rv_data && '959DEADDC0AB3667B55F5DA935F41798A0B47A7FF86CB7AD7984F794AC8D7805E05614A582804696'.
    rv_data = rv_data && 'B1C1D859A82ED39137F54997CE44E2635699C10ADAC0F0E767B26EA105B10560E0B4773C78128CBF'.
    rv_data = rv_data && '6BA93A165709BCE7C0F6543DF8DAA923768DFE55425B49F3D9ED89C98E1F022367BD281CA2AD8285'.
    rv_data = rv_data && 'A4E174E3DA51AEAC64FBC104210417BD61CF22F4747868DD00EDFC50C77495A9DA53084E2E8387CC'.
    rv_data = rv_data && '978E7E10F24BF8717C480363349744554BBFBF72FE2DA1C7B48B570F8CCF9A0C56A926F6A22DC5A5'.
    rv_data = rv_data && '76B3CF25339F7DD0198533F6F58243C5509A294852223C966360F257490E5B195869D92FDA50811F'.
    rv_data = rv_data && '2ED2EE4E244E6FE7EFBEA20891C8930E78A19F6DE454EAFB1A16FDC3DD0E4140413F653555186300'.
    rv_data = rv_data && '000020BA43BE74D49D39E6F2F3CE96B3565DE83D1161892A48A3400CD46BC75715127E0000019400'.
    rv_data = rv_data && '00000C7273612D736861322D323536000001809BD24381EF4C3AE7A16E2E4C1B1FF1CE8E96C62D94'.
    rv_data = rv_data && 'EF5AEB606B617F39041A6075520280C6A95A57F59F6CC11907ED37C284119DBCF05CE026FE6A6AA6'.
    rv_data = rv_data && '987660743E6991CA5CB065DBB88CF6138E50E80AD04E7FF07809EE9B706A1358D17D1410FEE99EA2'.
    rv_data = rv_data && '64B066E1FCB0AB417120DBC2A360E05C11B0B11D2A249E2271C9219E66F9B06477F23539D9DECD7E'.
    rv_data = rv_data && 'C39B3E8145F50B8F8DEA7817953A4AF5FA3D5618AE8C88D0E0F747FBCDA5B2F676FFB5C90F66F8AC'.
    rv_data = rv_data && 'FD700E099F46665D27DAFF9CBA73F5E0A0B3883445BBCBC0D4F6506261D559CCE581DAF46CD9223B'.
    rv_data = rv_data && 'A1454B5DC8D8E2E78BA179E4FE52C673E3F6134A762764B21C8772A79A3C0B758DA6BBA2B1E59AB3'.
    rv_data = rv_data && 'A4B6230605F462B3BFC4C33310403761270A5D2A0F1AED96C64167FC3B6A399700D9BC83C81B8F0E'.
    rv_data = rv_data && 'B9328F532C2A57A68EF8F724F542898D162976CDA16495BA4B7795DD284A89F38F6143DB9F81E60B'.
    rv_data = rv_data && 'D9E6E8ABD1317E92D40E81FD694A7694D863CAC54C6F1C384CB55C494C6B53DB449C0CC293906C43'.
    rv_data = rv_data && '28544500000000000000000000000000000C0A15000000000000000000008C2B279D629E8C79EE7A'.
    rv_data = rv_data && 'C1F2CFFA273FFCDFD2749596C3CA4C2FDB49BF34653317FE0BB987E565A55E5096467B7CCC3B8E40'.
    rv_data = rv_data && 'A0EF6148056675879A43623839DE37A543108B931E21EA41A044009F3EBC1267F9FFD62C10583886'.
    rv_data = rv_data && '8F1368B36E9B1778A85FDF97F940645706A139B69000FB87AC5D8A3EDD8FD2BD75795AEE8288E80C'.
    rv_data = rv_data && 'DD8087767BF5D0D8A8E50D1852C7CFA0AC09C0876211EC4ADF8397CC485C6231EA29F39E6F7ADFED'.
    rv_data = rv_data && 'B2DFB39E5B6EB0BD9300084B7829263ADD0731A0CD877122CC9716D42DDAEA651745DF0A0788B3F1'.
    rv_data = rv_data && '6142E2088A0EA17071EBDA10077F61199BF79E3756183D66CA710B0E2C6C43411DA61A25DF858C10'.
    rv_data = rv_data && '174F4F31C1DDDA5EA04B8A573151E4471BACE3AE68684052F1C2B8658230F890972F7BAF9B2A1B7F'.
    rv_data = rv_data && '433DC994D9E334791D12DF147705F5DF1241930BE30FBAA036AD14472CF62F068BE85E061EFF9D0F'.
    rv_data = rv_data && '6083276698BF04DA08452FE6E7CDD649773F604473CC27C22FD1FF3BBF7E78001D3A9AA697DC7484'.
    rv_data = rv_data && 'D64AF8B4D8628BAACC88CF5B73C8CA15A43CACEBEB5FC22BE7EBC7CA7D399B536D6A219F6DDE14C0'.
    rv_data = rv_data && '528CD9F298EB07A7EE2C9AFBBB72B09C2355B01929511A63DA67935DFED0CA64A28B42ED84D6DEC1'.
    rv_data = rv_data && 'F2307F79C128D14DE2D30EF95FBB6BC5CD2960BAB3300A4CCD98CF47695B7667A7019D5E4F8C95BF'.
    rv_data = rv_data && '2C10699FB50DF4B802D87DE6FBD6B6DEF9BC5DA2CF1E69F64BE3E1A68CF897CB6F0891CDE1429B89'.
    rv_data = rv_data && '7D808F557D14A48689EE94B61411813DF1754A125DED485D7CB5127721C23A5283AB4CD0FCE1B243'.
    rv_data = rv_data && '6BCA29847F5F04962CDBEA8F2B10967DEE94FDDC9CC4AB6601848649EA2CDD9960AC7DCC3AFC915F'.
    rv_data = rv_data && 'ED8B6E4FD039851094E1A3A7718A2A44EF4EEC55DBD9FE960F1E9BCC1DD2FCB5276F647FF512987C'.
    rv_data = rv_data && '32A38DA15778F995AF1F4487D153E3E1BEEAB71C91F4586B2207889127356893208AF9D3A21B8D57'.
    rv_data = rv_data && '0D2BF1BEB5A2556D2B2AB6F954265C90548739E9E6FF69DF5C528537E4F3DA4B892D4391EA7B2754'.
    rv_data = rv_data && 'C61AEB72F423629FAFF7A2B52A80F326F5AB4DF9C2F02199DC61F6CD9989F0A7897B0346A02DB08F'.
    rv_data = rv_data && 'D23A98734BEB3A2D1C4B671ADC1529C2E297AAC2C9BE9622842526D9F19C8CF31B34EB8E979366F9'.
    rv_data = rv_data && 'B705A947DC795F6215EA14CCC07EB1849B7E87A1A83F4DCECF60E1403F92946E27381454E5E9A704'.
    rv_data = rv_data && 'A4C6E9D3871D77D22E7F4954FCEF6E20F052437B745951C00BB5636E9C734D9EA8A81D8D8CB1E440'.
    rv_data = rv_data && '21C3FFB69B30898FA8889A2FE7C2F8DF1798FD4BF0B0860328339C324511CCECAAFDBD18D1A0FD7E'.
    rv_data = rv_data && 'BE98BE37590101494E49AAC3D796569F80549057073C69E8317CB1165B6F0861294507EBD1549DC7'.
    rv_data = rv_data && '938347FE8B015F4C052E26D913699C5DB9EF0AAA632366F8AF48E06A570DE0FEAFD52CE23ED21866'.
    rv_data = rv_data && 'A7DEDD9788F4DCE3FEA294498AD54445737146C6C5A33627F165E2890441237F5F15965ACE479BE9'.
    rv_data = rv_data && '5CB0C2D558D81689C9A06931EACC5A093E5BFFA7A2FBCCA520D33BBF3E4CE1AC4E97A3A9E4831590'.
    rv_data = rv_data && '3D4F2A54E92BF73312AF0AF8F89D93E2E8B371E3475EBD8CDA259350C4F54D06C3978A2E8896A142'.
    rv_data = rv_data && 'C8ADD027B3163740506D28212C049F87AEEAEBAE2E6C355CFC0295C03D879147531DB3794DC01FDD'.
    rv_data = rv_data && '3A55C3EA77EF55A2F4C2EBF63BFDC723F7EB0C3C6C2B725F8D647C90C2F4D565E875CD7BA6C93C3F'.
    rv_data = rv_data && '0868E2F34EA4E212ED4CC3F54303007E9AC596ECD962FAFEE13B28930CBEA450A919B26D94687D63'.
    rv_data = rv_data && '9694F9CBBB6C411BE34713EE2ED47128B785152FBE1F5033AE055F28844FE56255E6AD259355BA27'.
    rv_data = rv_data && 'B39905487FB5885EF613EC0BD96775E81AA40D1AA10BFBD5AA0D62CBCC0BB6F05235F9E7D68BE030'.
    rv_data = rv_data && 'F957D5A931874452A4E41672E4408A0AAC63A4C1C49CC5C468DD75EC1DC4637696068D745D0C16DC'.
    rv_data = rv_data && 'EA9FEDC32D124EC871A9CF8B264AF6D10E8020C802802DA5C40D31A096FAA267D59CB3EAE0F17D9F'.
    rv_data = rv_data && '4084CB0A1C8AD74D37B31276C72B10540059BBCE65B062B383685DCC895DB99DD78E7D203650EF90'.
    rv_data = rv_data && '2075F83E517A872DD4C37EF03AC1C466BD36818BBF4F7EE76E6AC8EE25F92679FA71599020960A8E'.
    rv_data = rv_data && '9A957FA7DD859D057746B13DFB1E1AB742ABA57286D853805444B67A5E4AEDB0B62A3D81D852CE33'.
    rv_data = rv_data && '0C1F17993B6982B4726C7DF95A9665768F1957A246A692F31D33E9B19A7212D76F91D1C3763B2BBA'.
    rv_data = rv_data && 'E979531537C827B49AA3774841A4048EE1223EEED11C4D6188C222955449616ECCE7C8E5910E71FE'.
    rv_data = rv_data && 'E0858AEDDD356B3206FD1F57D6E62ECD01DDC0056B3797356330F208958115A111A3D42CC61B7264'.
    rv_data = rv_data && 'D0CCBE8AFC5812709678077D0604037251CC51027E83F661E4C64AF1ED0A86BC3AF79B8E0DC5A258'.
    rv_data = rv_data && '7ACEB49EB9CC'.
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
    rv_data = rv_data && 'ABABABABABAB0000000C0A15ABABABABABABABABABABC929DD1A993A5AD414CCD4D3E9AF9B8B160D'.
    rv_data = rv_data && '0F5EDBE986AB29DB291D2CD63B4440600D3FDED133CBABF7A5AFBE6529600F2A7714D0AD0ADE342B'.
    rv_data = rv_data && '97FA632CA5E9A05726D81047E78DC4211707A0179426C136CF8EBFE0D002DB46AC9C427E9EE5A779'.
    rv_data = rv_data && '792EB2D87D4804272DF20D3C90C87254C31B1578C67931F3B5059B25CF2789EBA027F5943B14E1AE'.
    rv_data = rv_data && '4ABA0C4A7B52AB8B22DC149D17DA269FE0F5F860775CF1E145B2742F910BEA5FC1CDE3A993B280E9'.
    rv_data = rv_data && 'FF3EBC1530975452948933B24246B682F148DF3278A38A25AFDED4ADAE8B7308CBF68588DC943856'.
    rv_data = rv_data && '304F7A3671834FC83014844E23D7F25D106115CCB922FC24F2F8860252C1F01166C5FA24347F6D03'.
    rv_data = rv_data && '5F09275982EAF7C97028AB3B2BD0EADA523D665DAFFB9DADAEFCF47699652DBD5CB4ECF325C46473'.
    rv_data = rv_data && '7A1B35963027056CFB4241C465BE0726CA3355BBBD0A17C5D05A5BD2F2F48ECDC684DDDED0BC43AA'.
    rv_data = rv_data && 'B975F269B664D20C0EF1D6F4323B03CFA3C15D7B58E4B09BAA6D315534A226A0BD0C38E6DE896E34'.
    rv_data = rv_data && '1AC6F853296FB7A3BD431A211D668E49CDBD697A8A56BEAC9376F447E4B07BE56542282AB924FDE1'.
    rv_data = rv_data && 'BD24B893CC64C2AB8D6BCBF5BABC01C658569F4A89F0FCFA54D60E78B75150719C272D95371C1EE4'.
    rv_data = rv_data && '60956CCAD061A0521260A56756A37E8EDD680E879BAFB83000FF4125DE9538855C0F980099DEA5E0'.
    rv_data = rv_data && '9592B08654DBD5FAF66DCFA30BF3C64F11E1174A87D90C977D1B8769E1376F084ECF9899E4675D83'.
    rv_data = rv_data && '0264EF3F71702C16BA17777B8625D499747BDA05FA8BF241867F41D3FAF1081278B345A8DB44E7C3'.
    rv_data = rv_data && 'EDB9A57D0BF46F8CB8C4003E38394F7C2A2B07BBCB9B56EA5B2E4D0D1770A529D19A17E24C25A1FC'.
    rv_data = rv_data && '0C86937AF1B4EB1A18148CF5F83BD38C6F501314D2B29982350E0AF5F7D8A931D4AFBA03EDADB887'.
    rv_data = rv_data && '1A790A0912635D23AEBCE6C3702817BA536E7A63AA2AF72B7FCC95597E23'.
  ENDMETHOD.

ENDCLASS.
