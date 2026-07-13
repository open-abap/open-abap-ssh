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
    METHODS empty_command_state FOR TESTING RAISING cx_static_check.
    METHODS execute_early_failure FOR TESTING RAISING cx_static_check.
    METHODS utf8_credentials FOR TESTING RAISING cx_static_check.
    METHODS recorded_session FOR TESTING RAISING cx_static_check.
    METHODS recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS recorded_outbound
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
    cl_abap_unit_assert=>assert_false( lo_ssh->mv_command_done ).
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
    lo_ssh->mv_command_done = abap_true.
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
    cl_abap_unit_assert=>assert_true( lo_ssh->mv_execute_started ).
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

ENDCLASS.
