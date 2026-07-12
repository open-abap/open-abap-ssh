CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE.

  PUBLIC SECTION.

    INTERFACES zif_oassh_socket_handler.

    CLASS-METHODS connect
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string
        iv_user TYPE string
        iv_password TYPE string OPTIONAL
        iv_private_seed TYPE xstring OPTIONAL
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
      RETURNING
        VALUE(ro_ssh) TYPE REF TO zcl_oassh
      RAISING
        cx_static_check.

    METHODS execute
      IMPORTING
        iv_command         TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_output) TYPE string
      RAISING
        cx_static_check.
    METHODS get_stderr
      RETURNING
        VALUE(rv_output) TYPE string.
    METHODS get_exit_status
      RETURNING
        VALUE(rv_status) TYPE i.
    METHODS get_disconnect_reason
      RETURNING
        VALUE(rv_reason) TYPE i.
    METHODS close.

    METHODS constructor
      IMPORTING
        ii_socket TYPE REF TO zif_oassh_socket
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
        iv_user TYPE string
        iv_password TYPE string OPTIONAL
        iv_private_seed TYPE xstring OPTIONAL.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      BEGIN OF gc_state,
        protocol_version_exchange TYPE i VALUE 1,
        key_exchange              TYPE i VALUE 2,
        encrypted                 TYPE i VALUE 3,
      END OF gc_state.
    DATA mi_socket TYPE REF TO zif_oassh_socket.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    DATA mo_plain_packet TYPE REF TO zcl_oassh_packet.
    DATA mo_transport TYPE REF TO zcl_oassh_transport.
    DATA mv_state  TYPE i.
    DATA mv_client_version TYPE xstring.
    DATA mv_user TYPE xstring.
    DATA mv_password TYPE xstring.
    DATA mv_private_seed TYPE xstring.
    DATA mv_enc_packet_length TYPE i.
    DATA mo_channel TYPE REF TO zcl_oassh_channel.
    DATA mv_command TYPE string.
    DATA mv_command_done TYPE abap_bool.
    DATA mv_disconnected TYPE abap_bool.
    DATA mv_disconnect_reason TYPE i.

    METHODS handle_transport_message
      IMPORTING
        iv_payload         TYPE xstring
      RETURNING
        VALUE(rv_handled)  TYPE abap_bool.
    METHODS handle
      RAISING
        cx_static_check.
    METHODS process_version
      RAISING
        cx_static_check.
    METHODS process_kex
      RAISING
        cx_static_check.
    METHODS process_encrypted
      RAISING
        cx_static_check.
    METHODS start_channel
      RAISING
        cx_static_check.
    METHODS process_global_request
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
ENDCLASS.



CLASS zcl_oassh IMPLEMENTATION.


  METHOD connect.

    DATA li_socket TYPE REF TO zif_oassh_socket.

    li_socket = NEW zcl_oassh_socket_apc(
      iv_host = iv_host
      iv_port = iv_port ).

    CREATE OBJECT ro_ssh
      EXPORTING
        ii_socket        = li_socket
        ii_random        = ii_random
        ii_host_verifier = ii_host_verifier
        iv_user          = iv_user
        iv_password      = iv_password
        iv_private_seed  = iv_private_seed.

    li_socket->set_handler( ro_ssh ).
    li_socket->connect( ).

  ENDMETHOD.


  METHOD execute.
* Socket callbacks keep driving authentication while WAIT yields. Once the
* transport authenticates, start_channel sends CHANNEL_OPEN and callbacks
* drive the channel until the peer closes it.
    ASSERT mv_command IS INITIAL.
    ASSERT iv_timeout_seconds > 0.
    mv_command = iv_command.
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    mi_socket->wait( iv_timeout_seconds ).
    IF mv_command_done <> abap_true.
      mi_socket->close( ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    ASSERT mo_channel IS BOUND.
    ASSERT mo_channel->get_state( ) = zcl_oassh_channel=>c_state-closed.
    rv_output = zcl_oassh_ascii=>from_xstring_text( mo_channel->get_stdout( ) ).
  ENDMETHOD.


  METHOD get_stderr.
    IF mo_channel IS BOUND.
      rv_output = zcl_oassh_ascii=>from_xstring_text( mo_channel->get_stderr( ) ).
    ENDIF.
  ENDMETHOD.


  METHOD get_exit_status.
    rv_status = -1.
    IF mo_channel IS BOUND.
      rv_status = mo_channel->get_exit_status( ).
    ENDIF.
  ENDMETHOD.


  METHOD close.
    mi_socket->close( ).
  ENDMETHOD.


  METHOD get_disconnect_reason.
    rv_reason = mv_disconnect_reason.
  ENDMETHOD.


  METHOD handle_transport_message.
* RFC 4253 section 11: transport-layer messages that may arrive in any state.
* Handle them centrally so the phase/auth/channel dispatchers never see them.
    DATA ls_disconnect TYPE zcl_oassh_message_1=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    IF iv_payload IS INITIAL.
      RETURN.
    ENDIF.
    lo_stream = NEW #( iv_payload ).
    CASE iv_payload(1).
      WHEN zcl_oassh_message_1=>gc_message_id. " DISCONNECT
        ls_disconnect = zcl_oassh_message_1=>parse( lo_stream ).
        mv_disconnected = abap_true.
        mv_disconnect_reason = ls_disconnect-reason_code.
        mv_command_done = abap_true.
        rv_handled = abap_true.
      WHEN zcl_oassh_message_2=>gc_message_id. " IGNORE
        zcl_oassh_message_2=>parse( lo_stream ).
        rv_handled = abap_true.
      WHEN zcl_oassh_message_3=>gc_message_id. " UNIMPLEMENTED
        zcl_oassh_message_3=>parse( lo_stream ).
        rv_handled = abap_true.
      WHEN zcl_oassh_message_4=>gc_message_id. " DEBUG
        zcl_oassh_message_4=>parse( lo_stream ).
        rv_handled = abap_true.
      WHEN OTHERS.
        rv_handled = abap_false.
    ENDCASE.
  ENDMETHOD.


  METHOD constructor.
    mi_socket = ii_socket.
    mi_random = ii_random.
    mv_user = zcl_oassh_ascii=>to_xstring( iv_user ).
    mv_password = zcl_oassh_ascii=>to_xstring( iv_password ).
    mv_private_seed = iv_private_seed.
    CREATE OBJECT mo_stream.
    mo_plain_packet = NEW #( ii_random = mi_random ).
    mo_transport = NEW #(
      ii_random        = mi_random
      ii_host_verifier = ii_host_verifier ).
  ENDMETHOD.


  METHOD handle.
* Each phase runs in its own method: the transpiler mis-scopes the sy-index
* backup variable for a RETURN inside a loop that is nested in a CASE branch,
* so keeping one loop per method avoids the generated ReferenceError.
* State transitions fall through within a single call: version -> kex -> auth.
    IF mv_state = gc_state-protocol_version_exchange.
      process_version( ).
    ENDIF.
    IF mv_state = gc_state-key_exchange.
      process_kex( ).
    ENDIF.
    IF mv_state = gc_state-encrypted.
      process_encrypted( ).
    ENDIF.
  ENDMETHOD.


  METHOD process_version.
* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
    DATA lv_version_data TYPE xstring.
    DATA lv_version_length TYPE i.
    DATA lv_offset TYPE i.
    DATA lv_server_version TYPE xstring.
    DATA lv_payload TYPE xstring.
    lv_version_data = mo_stream->get( ).
    lv_version_length = xstrlen( lv_version_data ).
    WHILE lv_offset + 1 < lv_version_length.
      IF lv_version_data+lv_offset(2) = zcl_oassh_ascii=>c_cr_lf.
        lv_server_version = mo_stream->take( lv_offset ).
        mo_stream->take( 2 ).
        ASSERT lv_server_version(4) = '5353482D'.
        lv_payload = mo_transport->start_kex(
          iv_client_version = mv_client_version
          iv_server_version = lv_server_version ).
        mi_socket->send( mo_plain_packet->encode( lv_payload ) ).
        mv_state = gc_state-key_exchange.
        RETURN.
      ENDIF.
      lv_offset = lv_offset + 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD process_kex.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7
    DATA lv_length TYPE i.
    DATA lv_total_length TYPE i.
    DATA lv_wire TYPE xstring.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    DATA lv_message_id TYPE i.
    DATA lv_max_length TYPE i.
    lv_max_length = zcl_oassh_packet=>c_max_packet_length - 4.
    WHILE mo_stream->get_length( ) >= 8.
      lv_length = mo_stream->uint32_decode_peek( ).
      IF lv_length < 12.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      IF lv_length > lv_max_length.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
      ENDIF.
      lv_total_length = lv_length + 4.
      IF mo_stream->get_length( ) < lv_total_length.
        RETURN.
      ENDIF.
      lv_wire = mo_stream->take( lv_total_length ).
      lv_payload = mo_plain_packet->decode( lv_wire ).
      lv_message_id = lv_payload(1).
      IF mo_transport->is_strict_kex( ) = abap_true
          AND mo_transport->is_initial_kex( ) = abap_true.
        ASSERT lv_message_id = 20 OR lv_message_id = 21
          OR ( lv_message_id >= 30 AND lv_message_id <= 49 ).
      ENDIF.
      IF handle_transport_message( lv_payload ) = abap_true.
        CONTINUE.
      ENDIF.
      CASE mo_transport->get_state( ).
        WHEN zcl_oassh_transport=>c_state-kexinit_sent.
          lv_reply = mo_transport->receive_kexinit( lv_payload ).
          IF mo_transport->is_strict_kex( ) = abap_true.
* Strict KEX is negotiated by this packet, so verify retrospectively that it
* was the server's first binary packet (sequence zero before decode).
            ASSERT mo_plain_packet->get_receive_sequence( ) = 1.
          ENDIF.
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
        WHEN zcl_oassh_transport=>c_state-ecdh_sent.
          lv_reply = mo_transport->receive_kex_reply( lv_payload ).
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
          mo_transport->activate_outbound_keys( ).
        WHEN zcl_oassh_transport=>c_state-newkeys_sent.
          mo_transport->receive_newkeys( lv_payload ).
          mv_state = gc_state-encrypted.
          lv_reply = mo_transport->start_auth(
            iv_user         = mv_user
            iv_password     = mv_password
            iv_private_seed = mv_private_seed ).
          mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
          RETURN.
        WHEN OTHERS.
          ASSERT 1 = 2.
      ENDCASE.
    ENDWHILE.
  ENDMETHOD.


  METHOD process_encrypted.
* https://datatracker.ietf.org/doc/html/rfc4253#section-6
* the packet_length field is encrypted, so decrypt the first block to frame
    DATA lv_block TYPE xstring.
    DATA lv_rest TYPE xstring.
    DATA lv_mac TYPE xstring.
    DATA lv_remaining TYPE i.
    DATA lv_auth_length TYPE i.
    DATA lv_header_length TYPE i.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    WHILE mo_stream->get_length( ) > 0.
      IF mv_enc_packet_length = 0.
        lv_header_length = mo_transport->get_packet( )->get_header_length( ).
        IF mo_stream->get_length( ) < lv_header_length.
          RETURN.
        ENDIF.
        lv_block = mo_stream->take( lv_header_length ).
        mv_enc_packet_length = mo_transport->get_packet( )->decode_length( lv_block ).
      ENDIF.
      lv_auth_length = mo_transport->get_packet( )->get_auth_length( ).
      lv_header_length = mo_transport->get_packet( )->get_header_length( ).
      lv_remaining = mv_enc_packet_length + 4 - lv_header_length + lv_auth_length.
      IF mo_stream->get_length( ) < lv_remaining.
        RETURN.
      ENDIF.
      lv_rest = mo_stream->take( mv_enc_packet_length + 4 - lv_header_length ).
      lv_mac = mo_stream->take( lv_auth_length ).
      lv_payload = mo_transport->get_packet( )->decode_remainder(
        iv_rest = lv_rest
        iv_mac  = lv_mac ).
      mv_enc_packet_length = 0.
      IF handle_transport_message( lv_payload ) = abap_true.
        CONTINUE.
      ENDIF.
      CASE mo_transport->get_state( ).
        WHEN zcl_oassh_transport=>c_state-encrypted.
          IF lv_payload(1) = zcl_oassh_message_20=>gc_message_id.
* RFC 4253 section 9: the server may begin a fresh key exchange at any time.
* KEXINIT and ECDH_INIT are still protected by the current packet keys.
            lv_reply = mo_transport->start_rekey( ).
            mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
            lv_reply = mo_transport->receive_kexinit( lv_payload ).
            mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
            CONTINUE.
          ENDIF.
        WHEN zcl_oassh_transport=>c_state-ecdh_sent.
          lv_reply = mo_transport->receive_kex_reply( lv_payload ).
          mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
          mo_transport->activate_outbound_keys( ).
          CONTINUE.
        WHEN zcl_oassh_transport=>c_state-newkeys_sent.
          mo_transport->receive_newkeys( lv_payload ).
          CONTINUE.
      ENDCASE.
      IF mo_transport->get_auth_state( ) <> zcl_oassh_transport=>c_auth_state-authenticated.
        lv_reply = mo_transport->receive_auth( lv_payload ).
        IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated
            AND mv_command IS NOT INITIAL.
          start_channel( ).
        ENDIF.
      ELSEIF lv_payload(1) = '50'. " SSH_MSG_GLOBAL_REQUEST (80)
        lv_reply = process_global_request( lv_payload ).
      ELSEIF mo_channel IS BOUND.
        lv_reply = mo_channel->receive( lv_payload ).
        CASE mo_channel->get_state( ).
          WHEN zcl_oassh_channel=>c_state-open.
            lv_reply = mo_channel->exec( mv_command ).
          WHEN zcl_oassh_channel=>c_state-closed.
            mv_command_done = abap_true.
        ENDCASE.
      ELSE.
        ASSERT 1 = 2.
      ENDIF.
      IF lv_reply IS NOT INITIAL.
        mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
      ENDIF.
    ENDWHILE.
  ENDMETHOD.


  METHOD start_channel.
    DATA lv_payload TYPE xstring.
    ASSERT mo_channel IS NOT BOUND.
    mo_channel = NEW #( ).
    lv_payload = mo_channel->open( ).
    mi_socket->send( mo_transport->get_packet( )->encode( lv_payload ) ).
  ENDMETHOD.


  METHOD process_global_request.
* RFC 4254 section 4. OpenSSH sends hostkeys-00@openssh.com after auth.
* It is an optional extension; reject requests asking for a reply and ignore
* any request-specific trailing fields.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_want_reply TYPE abap_bool.
    lo_stream = NEW #( iv_payload ).
    ASSERT lo_stream->take( 1 ) = '50'.
    lo_stream->string_decode( ).
    lv_want_reply = lo_stream->boolean_decode( ).
    IF lv_want_reply = abap_true.
      rv_payload = '52'. " SSH_MSG_REQUEST_FAILURE (82)
    ENDIF.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_close.
    RETURN.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_error.
    mv_command_done = abap_true.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~is_complete.
    rv_complete = mv_command_done.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_message.
    mo_stream->append( iv_data ).
    handle( ).
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_open.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    DATA lv_xstr TYPE xstring.
    mv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ). "#EC NOTEXT
    lv_xstr = mv_client_version && zcl_oassh_ascii=>c_cr_lf.

    mi_socket->send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.
ENDCLASS.
