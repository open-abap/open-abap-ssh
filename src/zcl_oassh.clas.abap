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
        ii_random TYPE REF TO zif_oassh_random OPTIONAL
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
    METHODS sftp_download
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        cx_static_check.
    METHODS sftp_upload
      IMPORTING
        iv_path            TYPE string
        iv_data            TYPE xstring
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        cx_static_check.
    METHODS sftp_stat
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rs_attrs) TYPE zcl_oassh_sftp=>ty_attrs
      RAISING
        cx_static_check.
    METHODS sftp_lstat
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rs_attrs) TYPE zcl_oassh_sftp=>ty_attrs
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
        iv_password_supplied TYPE abap_bool DEFAULT abap_true
        iv_private_seed TYPE xstring OPTIONAL.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      BEGIN OF gc_state,
        protocol_version_exchange TYPE i VALUE 1,
        key_exchange              TYPE i VALUE 2,
        encrypted                 TYPE i VALUE 3,
      END OF gc_state.
    CONSTANTS:
      BEGIN OF gc_operation,
        none          TYPE i VALUE 0,
        execute       TYPE i VALUE 1,
        sftp_download TYPE i VALUE 2,
        sftp_upload   TYPE i VALUE 3,
        sftp_stat     TYPE i VALUE 4,
        sftp_lstat    TYPE i VALUE 5,
      END OF gc_operation.
    DATA mi_socket TYPE REF TO zif_oassh_socket.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    DATA mo_plain_packet TYPE REF TO zcl_oassh_packet.
    DATA mo_transport TYPE REF TO zcl_oassh_transport.
    DATA mv_state  TYPE i.
    DATA mv_client_version TYPE xstring.
    DATA mv_version_prefix_checked TYPE abap_bool.
    DATA mv_version_is_ssh TYPE abap_bool.
    DATA mv_user TYPE xstring.
    DATA mv_password TYPE xstring.
    DATA mv_password_supplied TYPE abap_bool.
    DATA mv_private_seed TYPE xstring.
    DATA mv_plain_packet_length TYPE i.
    DATA mv_enc_packet_length TYPE i.
    DATA mo_channel TYPE REF TO zcl_oassh_channel.
    DATA mo_sftp TYPE REF TO zcl_oassh_sftp.
    DATA mv_command TYPE string.
    DATA mv_sftp_path TYPE string.
    DATA mv_sftp_upload_data TYPE xstring.
    DATA mv_sftp_outbound TYPE xstring.
    DATA mv_operation TYPE i.
    DATA mv_operation_started TYPE abap_bool.
    DATA mv_operation_done TYPE abap_bool.
    DATA mv_disconnected TYPE abap_bool.
    DATA mv_disconnect_reason TYPE i.

    METHODS handle_transport_message
      IMPORTING
        iv_payload         TYPE xstring
      RETURNING
        VALUE(rv_handled)  TYPE abap_bool
      RAISING zcx_oassh_error.
    METHODS handle
      RAISING
        cx_static_check.
    METHODS process_version
      RAISING
        cx_static_check.
    CLASS-METHODS validate_server_identification
      IMPORTING
        iv_identification TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS process_kex
      RAISING
        cx_static_check.
    METHODS process_encrypted
      RAISING
        cx_static_check.
    METHODS start_channel
      RAISING
        cx_static_check.
    METHODS advance_channel
      IMPORTING
        iv_payload TYPE xstring
      RAISING
        cx_static_check.
    METHODS send_encrypted
      IMPORTING
        iv_payload TYPE xstring
      RAISING
        cx_static_check.
    METHODS queue_sftp_output
      IMPORTING
        iv_data TYPE xstring.
    METHODS flush_sftp_output
      RAISING
        cx_static_check.
    METHODS sftp_attributes
      IMPORTING
        iv_path            TYPE string
        iv_lstat           TYPE abap_bool
        iv_timeout_seconds TYPE i
      RETURNING
        VALUE(rs_attrs) TYPE zcl_oassh_sftp=>ty_attrs
      RAISING
        cx_static_check.
    METHODS process_global_request
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS reject_channel_open
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    CLASS-METHODS is_recognized_message
      IMPORTING
        iv_message_number TYPE i
      RETURNING
        VALUE(rv_recognized) TYPE abap_bool.
    METHODS unimplemented_reply
      IMPORTING
        io_packet       TYPE REF TO zcl_oassh_packet
      RETURNING
        VALUE(rv_reply) TYPE xstring.
ENDCLASS.



CLASS zcl_oassh IMPLEMENTATION.


  METHOD connect.

    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.

    IF ii_random IS BOUND.
      li_random = ii_random.
    ELSE.
      li_random = NEW zcl_oassh_random_secure( ).
    ENDIF.

    li_socket = NEW zcl_oassh_socket_apc(
      iv_host = iv_host
      iv_port = iv_port ).

    ro_ssh = NEW #(
      ii_socket            = li_socket
      ii_random            = li_random
      ii_host_verifier     = ii_host_verifier
      iv_user              = iv_user
      iv_password          = iv_password
      iv_password_supplied = xsdbool( iv_password IS SUPPLIED )
      iv_private_seed      = iv_private_seed ).

    li_socket->set_handler( ro_ssh ).
    li_socket->connect( ).

  ENDMETHOD.


  METHOD execute.
* Socket callbacks keep driving authentication while WAIT yields. Once the
* transport authenticates, start_channel sends CHANNEL_OPEN and callbacks
* drive the channel until the peer closes it.
    IF mv_operation_started = abap_true.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-execute.
    mv_command = iv_command.
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    mi_socket->wait( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
* A socket error or SSH disconnect can complete the wait before a channel is
* opened or closed. Report that as a typed operation failure, never ASSERT.
    IF mo_channel IS NOT BOUND.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    rv_output = zcl_oassh_ascii=>from_xstring_text( mo_channel->get_stdout( ) ).
  ENDMETHOD.


  METHOD sftp_download.
* The public operation remains binary-safe end to end. Authentication and
* channel setup share the execute callback flow; only the channel operation
* selected after open differs.
    DATA lv_status TYPE i.
    IF mv_operation_started = abap_true.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_download.
    mv_sftp_path = iv_path.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    mi_socket->wait( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      zcx_oassh_error=>raise(
        iv_reason      = zcx_oassh_error=>c_reason-sftp_status
        iv_sftp_status = lv_status ).
    ENDIF.
    rv_data = mo_sftp->get_data( ).
  ENDMETHOD.


  METHOD sftp_upload.
* Upload completion means every WRITE was acknowledged and the remote handle
* and SSH channel both completed their close handshakes.
    DATA lv_status TYPE i.
    IF mv_operation_started = abap_true.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_upload.
    mv_sftp_path = iv_path.
    mv_sftp_upload_data = iv_data.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    mi_socket->wait( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      zcx_oassh_error=>raise(
        iv_reason      = zcx_oassh_error=>c_reason-sftp_status
        iv_sftp_status = lv_status ).
    ENDIF.
  ENDMETHOD.


  METHOD sftp_stat.
    rs_attrs = sftp_attributes(
      iv_path            = iv_path
      iv_lstat           = abap_false
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_lstat.
    rs_attrs = sftp_attributes(
      iv_path            = iv_path
      iv_lstat           = abap_true
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_attributes.
    DATA lv_status TYPE i.
    IF mv_operation_started = abap_true.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    mv_operation_started = abap_true.
    IF iv_lstat = abap_true.
      mv_operation = gc_operation-sftp_lstat.
    ELSE.
      mv_operation = gc_operation-sftp_stat.
    ENDIF.
    mv_sftp_path = iv_path.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    mi_socket->wait( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-timeout ).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      zcx_oassh_error=>raise(
        iv_reason      = zcx_oassh_error=>c_reason-sftp_status
        iv_sftp_status = lv_status ).
    ENDIF.
    rs_attrs = mo_sftp->get_attrs( ).
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
    IF rv_handled = abap_true AND lo_stream->get_length( ) <> 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF rv_handled = abap_true
        AND iv_payload(1) = zcl_oassh_message_1=>gc_message_id.
      mv_disconnected = abap_true.
      mv_disconnect_reason = ls_disconnect-reason_code.
      mv_operation_done = abap_true.
    ENDIF.
  ENDMETHOD.


  METHOD constructor.
    mi_socket = ii_socket.
    mi_random = ii_random.
* RFC 4252 sections 5 and 8 require UTF-8 for user names and passwords.
    mv_user = zcl_oassh_ascii=>to_xstring_text( iv_user ).
    mv_password = zcl_oassh_ascii=>to_xstring_text( iv_password ).
    mv_password_supplied = iv_password_supplied.
    mv_private_seed = iv_private_seed.
    mo_stream = NEW #( ).
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
    DATA lv_line_length TYPE i.
    DATA lv_server_version TYPE xstring.
    DATA lv_payload TYPE xstring.
    CONSTANTS lc_max_identification TYPE i VALUE 255.
    CONSTANTS lc_max_prebanner TYPE i VALUE 35000.
* APC delivers fixed one-byte frames. Scan pending chunks incrementally and
* materialize a line only after its CR LF terminator has been found.
    WHILE 1 = 1.
      lv_version_length = mo_stream->get_length( ).
      IF mv_version_prefix_checked = abap_false AND lv_version_length >= 4.
        lv_version_data = mo_stream->get( ).
        mv_version_is_ssh = xsdbool( lv_version_data(4) = '5353482D' ).
        mv_version_prefix_checked = abap_true.
      ENDIF.
      lv_line_length = mo_stream->find_cr_lf( ).
      IF lv_line_length >= 0.
        IF lv_line_length + 2 > lc_max_prebanner.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
        ENDIF.
        lv_server_version = mo_stream->take( lv_line_length ).
        mo_stream->take( 2 ).
* RFC 4253 section 4.2 permits server information lines before the SSH
* identification. Ignore them, but treat a malformed SSH-prefixed line as a
* protocol error rather than terminating the ABAP session with ASSERT.
        IF mv_version_is_ssh = abap_false.
          CLEAR mv_version_prefix_checked.
          CLEAR mv_version_is_ssh.
          CONTINUE.
        ENDIF.
        validate_server_identification( lv_server_version ).
        lv_payload = mo_transport->start_kex(
          iv_client_version = mv_client_version
          iv_server_version = lv_server_version ).
        mi_socket->send( mo_plain_packet->encode( lv_payload ) ).
        mv_state = gc_state-key_exchange.
        RETURN.
      ENDIF.
* Once an SSH-prefixed line is recognizable it cannot still grow beyond the
* RFC's 255-byte limit while waiting for its terminating CR LF.
      IF mv_version_is_ssh = abap_true
          AND lv_version_length >= lc_max_identification.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
* RFC 4253 permits diagnostic lines but gives them no size limit. Bound an
* unterminated/non-SSH line at the transport ceiling to prevent unbounded
* pre-authentication buffering.
      IF lv_version_length > lc_max_prebanner.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
      ENDIF.
      RETURN.
    ENDWHILE.
  ENDMETHOD.


  METHOD validate_server_identification.
* RFC 4253 sections 4.2 and 5.1: SSH-2.0 and SSH-1.99 identify protocol 2;
* the complete line is at most 255 bytes including CR LF, NUL is forbidden,
* and softwareversion is a non-empty printable US-ASCII token without
* whitespace or '-'.
    DATA lv_offset TYPE i.
    DATA lv_byte TYPE x LENGTH 1.
    DATA lv_code TYPE i.
    DATA lv_software_length TYPE i.
    DATA lv_comment_started TYPE abap_bool.
    DATA lv_last_offset TYPE i.
    IF xstrlen( iv_identification ) + 2 > 255
        OR xstrlen( iv_identification ) < 9
        OR ( iv_identification(8) <> '5353482D322E302D'
          AND iv_identification(8) <> '5353482D312E39392D' ).
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_last_offset = xstrlen( iv_identification ) - 1.
    DO xstrlen( iv_identification ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_identification+lv_offset(1).
      IF lv_byte = '00'.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      IF lv_offset < 8 OR lv_comment_started = abap_true.
        CONTINUE.
      ENDIF.
      IF lv_byte = '20'.
        IF lv_software_length = 0
            OR lv_offset = lv_last_offset.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_comment_started = abap_true.
        CONTINUE.
      ENDIF.
      lv_code = lv_byte.
      IF lv_code < 33 OR lv_code > 126 OR lv_byte = '2D'.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_software_length = lv_software_length + 1.
    ENDDO.
    IF lv_software_length = 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD process_kex.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7
    DATA lv_total_length TYPE i.
    DATA lv_wire TYPE xstring.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    DATA lv_message_id TYPE i.
    DATA lv_unimplemented TYPE xstring.
    DATA lv_max_length TYPE i.
    lv_max_length = zcl_oassh_packet=>c_max_packet_length - 4.
    WHILE mo_stream->get_length( ) >= 8.
      IF mv_plain_packet_length = 0.
        mv_plain_packet_length = mo_stream->uint32_decode_peek( ).
        IF mv_plain_packet_length < 12.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        IF mv_plain_packet_length > lv_max_length.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
        ENDIF.
      ENDIF.
      lv_total_length = mv_plain_packet_length + 4.
      IF mo_stream->get_length( ) < lv_total_length.
        RETURN.
      ENDIF.
      lv_wire = mo_stream->take( lv_total_length ).
      CLEAR mv_plain_packet_length.
      lv_payload = mo_plain_packet->decode( lv_wire ).
      lv_message_id = lv_payload(1).
      IF mo_transport->is_strict_kex( ) = abap_true
          AND mo_transport->is_initial_kex( ) = abap_true
          AND lv_message_id <> 20
          AND lv_message_id <> 21
          AND ( lv_message_id < 30 OR lv_message_id > 49 ).
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      IF handle_transport_message( lv_payload ) = abap_true.
* RFC 4253 section 11.1: terminate immediately and accept no later data.
        IF mv_disconnected = abap_true.
          mi_socket->close( ).
          RETURN.
        ENDIF.
        CONTINUE.
      ENDIF.
      IF is_recognized_message( lv_message_id ) = abap_false.
        lv_unimplemented = unimplemented_reply( mo_plain_packet ).
        mi_socket->send( mo_plain_packet->encode( lv_unimplemented ) ).
        CONTINUE.
      ENDIF.
      CASE mo_transport->get_state( ).
        WHEN zcl_oassh_transport=>c_state-kexinit_sent.
          lv_reply = mo_transport->receive_kexinit( lv_payload ).
          IF mo_transport->is_strict_kex( ) = abap_true
              AND mo_plain_packet->get_receive_sequence( ) <> 1.
* Strict KEX is negotiated by this packet, so verify retrospectively that it
* was the server's first binary packet (sequence zero before decode).
            zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
          ENDIF.
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
        WHEN zcl_oassh_transport=>c_state-ecdh_sent.
          IF mo_transport->discard_guessed_packet( ) = abap_true.
            CONTINUE.
          ENDIF.
          lv_reply = mo_transport->receive_kex_reply( lv_payload ).
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
          mo_transport->activate_outbound_keys( ).
        WHEN zcl_oassh_transport=>c_state-newkeys_sent.
          mo_transport->receive_newkeys( lv_payload ).
          mv_state = gc_state-encrypted.
          lv_reply = mo_transport->start_auth(
            iv_user              = mv_user
            iv_password          = mv_password
            iv_password_supplied = mv_password_supplied
            iv_private_seed      = mv_private_seed ).
          CLEAR mv_private_seed.
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
    DATA lv_message_number TYPE i.
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
* RFC 4253 section 11.1: terminate immediately and accept no later data.
        IF mv_disconnected = abap_true.
          mi_socket->close( ).
          RETURN.
        ENDIF.
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
          IF mo_transport->discard_guessed_packet( ) = abap_true.
            CONTINUE.
          ENDIF.
          lv_reply = mo_transport->receive_kex_reply( lv_payload ).
          mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
          mo_transport->activate_outbound_keys( ).
          CONTINUE.
        WHEN zcl_oassh_transport=>c_state-newkeys_sent.
          mo_transport->receive_newkeys( lv_payload ).
          CONTINUE.
      ENDCASE.
      lv_message_number = lv_payload(1).
      IF is_recognized_message( lv_message_number ) = abap_false.
* RFC 4253 section 11.4: ignore unknown messages after replying with the
* rejected packet's sequence number, including across uint32 rollover.
        lv_reply = unimplemented_reply( mo_transport->get_packet( ) ).
        mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
        CONTINUE.
      ENDIF.
      IF mo_transport->get_auth_state( ) <> zcl_oassh_transport=>c_auth_state-authenticated.
        lv_reply = mo_transport->receive_auth( lv_payload ).
        IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated
            AND mv_operation_started = abap_true.
          start_channel( ).
        ENDIF.
      ELSEIF lv_payload(1) = '5A'. " SSH_MSG_CHANNEL_OPEN (90)
        lv_reply = reject_channel_open( lv_payload ).
      ELSEIF lv_payload(1) = '50'. " SSH_MSG_GLOBAL_REQUEST (80)
        lv_reply = process_global_request( lv_payload ).
      ELSEIF mo_channel IS BOUND.
        advance_channel( lv_payload ).
        CLEAR lv_reply.
      ELSE.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
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


  METHOD advance_channel.
* Keep channel plumbing generic while selecting the one-shot owner operation.
* Replies created by receive (window adjust / close echo) are sent before an
* SFTP request generated from the newly drained CHANNEL_DATA.
    DATA lv_reply TYPE xstring.
    DATA lv_sftp_input TYPE xstring.
    DATA lv_sftp_output TYPE xstring.
    lv_reply = mo_channel->receive( iv_payload ).
    send_encrypted( lv_reply ).
    CASE mo_channel->get_state( ).
      WHEN zcl_oassh_channel=>c_state-open.
        CASE mv_operation.
          WHEN gc_operation-execute.
            lv_reply = mo_channel->exec( mv_command ).
          WHEN gc_operation-sftp_download OR gc_operation-sftp_upload
              OR gc_operation-sftp_stat OR gc_operation-sftp_lstat.
            lv_reply = mo_channel->subsystem( 'sftp' ).
          WHEN OTHERS.
            zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
        ENDCASE.
        send_encrypted( lv_reply ).
      WHEN zcl_oassh_channel=>c_state-running.
        IF mv_operation = gc_operation-sftp_download
            OR mv_operation = gc_operation-sftp_upload
            OR mv_operation = gc_operation-sftp_stat
            OR mv_operation = gc_operation-sftp_lstat.
          flush_sftp_output( ).
          IF mo_sftp->get_state( ) = zcl_oassh_sftp=>c_state-created.
            CASE mv_operation.
              WHEN gc_operation-sftp_download.
                lv_sftp_output = mo_sftp->start_download( mv_sftp_path ).
              WHEN gc_operation-sftp_upload.
                lv_sftp_output = mo_sftp->start_upload(
                  iv_path = mv_sftp_path
                  iv_data = mv_sftp_upload_data ).
              WHEN gc_operation-sftp_stat OR gc_operation-sftp_lstat.
                lv_sftp_output = mo_sftp->start_stat(
                  iv_path  = mv_sftp_path
                  iv_lstat = xsdbool( mv_operation = gc_operation-sftp_lstat ) ).
            ENDCASE.
          ELSE.
            lv_sftp_input = mo_channel->drain_stdout( ).
            IF lv_sftp_input IS NOT INITIAL.
              lv_sftp_output = mo_sftp->receive( lv_sftp_input ).
            ENDIF.
          ENDIF.
          IF lv_sftp_output IS NOT INITIAL.
            queue_sftp_output( lv_sftp_output ).
            flush_sftp_output( ).
          ENDIF.
          IF mo_sftp->get_state( ) = zcl_oassh_sftp=>c_state-finished
              AND mv_sftp_outbound IS INITIAL.
            lv_reply = mo_channel->close( ).
            send_encrypted( lv_reply ).
          ENDIF.
        ENDIF.
      WHEN zcl_oassh_channel=>c_state-closed.
        mv_operation_done = abap_true.
    ENDCASE.
  ENDMETHOD.


  METHOD send_encrypted.
    IF iv_payload IS NOT INITIAL.
      mi_socket->send( mo_transport->get_packet( )->encode( iv_payload ) ).
    ENDIF.
  ENDMETHOD.


  METHOD queue_sftp_output.
    CONCATENATE mv_sftp_outbound iv_data INTO mv_sftp_outbound IN BYTE MODE.
  ENDMETHOD.


  METHOD flush_sftp_output.
* RFC 4254 section 5.2: never exceed either the current remote window or the
* peer's maximum packet size. WINDOW_ADJUST callbacks re-enter this method.
    DATA lv_capacity TYPE i.
    DATA lv_pending_length TYPE i.
    DATA lv_send_length TYPE i.
    DATA lv_payload TYPE xstring.
    DATA lv_remainder TYPE xstring.
    DATA lv_reply TYPE xstring.
    lv_capacity = mo_channel->get_send_capacity( ).
    WHILE mv_sftp_outbound IS NOT INITIAL AND lv_capacity > 0.
      lv_pending_length = xstrlen( mv_sftp_outbound ).
      lv_send_length = lv_pending_length.
      IF lv_send_length > lv_capacity.
        lv_send_length = lv_capacity.
      ENDIF.
      lv_payload = mv_sftp_outbound(lv_send_length).
      IF lv_send_length = lv_pending_length.
        CLEAR mv_sftp_outbound.
      ELSE.
        lv_remainder = mv_sftp_outbound+lv_send_length.
        mv_sftp_outbound = lv_remainder.
      ENDIF.
      lv_reply = mo_channel->data( lv_payload ).
      send_encrypted( lv_reply ).
      lv_capacity = mo_channel->get_send_capacity( ).
    ENDWHILE.
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
* A transport close before SSH channel completion makes the active operation
* impossible; release APC WAIT immediately and let execute return a typed
* channel failure.
    mv_operation_done = abap_true.
  ENDMETHOD.


  METHOD reject_channel_open.
* RFC 4254 sections 5.1 and 6.1: this client never accepts server-created
* channels, so return OPEN_ADMINISTRATIVELY_PROHIBITED for the sender channel.
    DATA lo_input TYPE REF TO zcl_oassh_stream.
    DATA lo_reply TYPE REF TO zcl_oassh_stream.
    DATA lv_message_id TYPE x LENGTH 1.
    DATA lv_sender_channel TYPE i.
    DATA lv_uint32 TYPE xstring.
    DATA lv_remaining TYPE i.
    DATA lv_empty TYPE xstring.
    lo_input = NEW #( iv_payload ).
    lv_message_id = lo_input->take( 1 ).
    IF lv_message_id <> '5A'.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lo_input->string_decode( ).
    lv_sender_channel = lo_input->uint32_decode( ).
    lv_uint32 = lo_input->take( 4 ). " initial window
    lv_uint32 = lo_input->take( 4 ). " maximum packet
* Channel-type-specific fields have no generic shape and are irrelevant when
* rejecting the open, but the complete bounded transport payload is consumed.
    lv_remaining = lo_input->get_length( ).
    lo_input->take( lv_remaining ).

    lo_reply = NEW #( ).
    lo_reply->append( '5C' ). " SSH_MSG_CHANNEL_OPEN_FAILURE (92)
    lo_reply->uint32_encode( lv_sender_channel ).
    lo_reply->uint32_encode( 1 ). " OPEN_ADMINISTRATIVELY_PROHIBITED
    lo_reply->string_encode( lv_empty ).
    lo_reply->string_encode( lv_empty ).
    rv_payload = lo_reply->get( ).
  ENDMETHOD.


  METHOD is_recognized_message.
* Transport messages whose ordering may still be invalid are recognized and
* left to the state machine. Only genuinely unknown numbers get UNIMPLEMENTED.
    IF iv_message_number = 5 OR iv_message_number = 6
        OR iv_message_number = 20 OR iv_message_number = 21
        OR iv_message_number = 30 OR iv_message_number = 31
        OR iv_message_number BETWEEN 50 AND 53
        OR iv_message_number = 60
        OR iv_message_number BETWEEN 80 AND 82
        OR iv_message_number BETWEEN 90 AND 100.
      rv_recognized = abap_true.
    ENDIF.
  ENDMETHOD.


  METHOD unimplemented_reply.
    DATA ls_unimplemented TYPE zcl_oassh_message_3=>ty_data.
    ls_unimplemented-message_id = zcl_oassh_message_3=>gc_message_id.
    ls_unimplemented-sequence_number = io_packet->get_last_receive_sequence( ).
    rv_reply = zcl_oassh_message_3=>serialize( ls_unimplemented )->get( ).
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_error.
    mv_operation_done = abap_true.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~is_complete.
    rv_complete = mv_operation_done.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_message.
* RFC 4253 section 11.1 forbids accepting data after DISCONNECT. A socket
* adapter may still deliver a callback that was already queued before close.
    IF mv_disconnected = abap_true.
      RETURN.
    ENDIF.
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
