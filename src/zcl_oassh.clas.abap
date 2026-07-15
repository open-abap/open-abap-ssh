CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE.

  PUBLIC SECTION.

    CLASS-METHODS connect
      IMPORTING
        iv_host          TYPE string
        iv_port          TYPE string
        iv_user          TYPE string
        iv_password      TYPE string OPTIONAL
        iv_private_seed  TYPE xstring OPTIONAL
        iv_ssl_id        TYPE ssfapplssl OPTIONAL
        ii_random        TYPE REF TO zif_oassh_random OPTIONAL
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
      RETURNING
        VALUE(ro_ssh)    TYPE REF TO zcl_oassh
      RAISING
        zcx_oassh_error.

    METHODS execute
      IMPORTING
        iv_command         TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_output)   TYPE string
      RAISING
        zcx_oassh_error.
* Multi-operation SFTP session: sftp_open( ) performs the channel, subsystem
* and INIT/VERSION handshake once, then the sftp_* methods below run inside
* that single session until sftp_close( ). Without sftp_open( ) each sftp_*
* method is one-shot (its own connection lifecycle), exactly as before.
* See docs/sftp-sessions.md.
    METHODS sftp_open
      IMPORTING
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        zcx_oassh_error.
    METHODS sftp_close
      IMPORTING
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        zcx_oassh_error.
    METHODS sftp_download
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_data)     TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS shell
      IMPORTING
        iv_input           TYPE xstring
        iv_terminal        TYPE string DEFAULT 'xterm'
        iv_columns         TYPE i DEFAULT 80
        iv_rows            TYPE i DEFAULT 24
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_output)   TYPE xstring
      RAISING
        zcx_oassh_error.
* Interactive exec: exec_open starts a command and returns while the channel
* stays open, so the caller can interleave binary stdin and stdout, for
* example to speak a request/response protocol such as git-upload-pack.
* The conversation ends with exec_close. See docs/interactive-exec.md.
    METHODS exec_open
      IMPORTING
        iv_command         TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        zcx_oassh_error.
    METHODS exec_write
      IMPORTING
        iv_data TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS exec_read
      IMPORTING
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rv_data)     TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS exec_eof
      RAISING
        zcx_oassh_error.
    METHODS exec_close
      IMPORTING
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        zcx_oassh_error.
    METHODS exec_is_closed
      RETURNING
        VALUE(rv_closed) TYPE abap_bool.
    METHODS sftp_upload
      IMPORTING
        iv_path            TYPE string
        iv_data            TYPE xstring
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING
        zcx_oassh_error.
    METHODS sftp_stat
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rs_attrs)    TYPE zcl_oassh_sftp=>ty_attrs
      RAISING
        zcx_oassh_error.
    METHODS sftp_lstat
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rs_attrs)    TYPE zcl_oassh_sftp=>ty_attrs
      RAISING
        zcx_oassh_error.
    METHODS sftp_list
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RETURNING
        VALUE(rt_names)    TYPE zcl_oassh_sftp=>ty_names
      RAISING
        zcx_oassh_error.
    METHODS sftp_mkdir
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING zcx_oassh_error.
    METHODS sftp_rmdir
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING zcx_oassh_error.
    METHODS sftp_remove
      IMPORTING
        iv_path            TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING zcx_oassh_error.
    METHODS sftp_rename
      IMPORTING
        iv_old_path        TYPE string
        iv_new_path        TYPE string
        iv_timeout_seconds TYPE i DEFAULT 300
      RAISING zcx_oassh_error.
    METHODS sftp_realpath
      IMPORTING
        iv_path                TYPE string
        iv_timeout_seconds     TYPE i DEFAULT 300
      RETURNING VALUE(rs_name) TYPE zcl_oassh_sftp=>ty_name
      RAISING zcx_oassh_error.
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
        ii_socket            TYPE REF TO zif_oassh_socket
        ii_random            TYPE REF TO zif_oassh_random
        ii_host_verifier     TYPE REF TO zif_oassh_host_verifier
        iv_host              TYPE string
        iv_port              TYPE string
        iv_user              TYPE string
        iv_password          TYPE string OPTIONAL
        iv_password_supplied TYPE abap_bool DEFAULT abap_true
        iv_private_seed      TYPE xstring OPTIONAL.
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
        sftp_list     TYPE i VALUE 6,
        sftp_mkdir    TYPE i VALUE 7,
        sftp_rmdir    TYPE i VALUE 8,
        sftp_remove   TYPE i VALUE 9,
        sftp_rename   TYPE i VALUE 10,
        sftp_realpath TYPE i VALUE 11,
        shell         TYPE i VALUE 12,
        exec_stream   TYPE i VALUE 13,
        sftp_session  TYPE i VALUE 14,
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
    DATA mv_shell_terminal TYPE string.
    DATA mv_shell_columns TYPE i.
    DATA mv_shell_rows TYPE i.
    DATA mv_shell_input TYPE xstring.
    DATA mv_shell_offset TYPE i.
    DATA mv_shell_eof_sent TYPE abap_bool.
    DATA mv_sftp_path TYPE string.
    DATA mv_sftp_path2 TYPE string.
    DATA mv_sftp_upload_data TYPE xstring.
    DATA mv_sftp_outbound TYPE xstring.
    DATA mv_exec_outbound TYPE xstring.
    DATA mv_operation TYPE i.
    DATA mv_operation_started TYPE abap_bool.
    DATA mv_operation_done TYPE abap_bool.
    DATA mv_sftp_session TYPE abap_bool.
    DATA mv_sftp_session_broken TYPE abap_bool.
    DATA mv_disconnected TYPE abap_bool.
    DATA mv_disconnect_reason TYPE i.

    METHODS handle_transport_message
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_handled) TYPE abap_bool
      RAISING zcx_oassh_error.
    METHODS handle
      RAISING
        zcx_oassh_error.
    METHODS send_version
      RAISING
        zcx_oassh_error.
    METHODS pump
      IMPORTING
        iv_timeout_seconds TYPE i
      RAISING
        zcx_oassh_error.
    METHODS pump_sftp_session
      IMPORTING
        iv_timeout_seconds TYPE i
      RAISING
        zcx_oassh_error.
    METHODS sftp_session_run
      IMPORTING
        iv_request         TYPE xstring
        iv_timeout_seconds TYPE i
      RAISING
        zcx_oassh_error.
    METHODS process_inbound
      IMPORTING
        iv_data TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS process_version
      RAISING
        zcx_oassh_error.
    CLASS-METHODS validate_server_identification
      IMPORTING
        iv_identification TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS process_kex
      RAISING
        zcx_oassh_error.
    METHODS process_encrypted
      RAISING
        zcx_oassh_error.
    METHODS start_channel
      RAISING
        zcx_oassh_error.
    METHODS advance_channel
      IMPORTING
        iv_payload TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS send_encrypted
      IMPORTING
        iv_payload TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS queue_sftp_output
      IMPORTING
        iv_data TYPE xstring.
    METHODS flush_sftp_output
      RAISING
        zcx_oassh_error.
    METHODS flush_shell_input
      RAISING
        zcx_oassh_error.
    METHODS flush_exec_output
      RAISING
        zcx_oassh_error.
    METHODS sftp_attributes
      IMPORTING
        iv_path            TYPE string
        iv_lstat           TYPE abap_bool
        iv_timeout_seconds TYPE i
      RETURNING
        VALUE(rs_attrs)    TYPE zcl_oassh_sftp=>ty_attrs
      RAISING
        zcx_oassh_error.
    METHODS sftp_mutation
      IMPORTING
        iv_operation       TYPE i
        iv_path            TYPE string
        iv_path2           TYPE string OPTIONAL
        iv_timeout_seconds TYPE i
      RAISING zcx_oassh_error.
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
        iv_message_number    TYPE i
      RETURNING
        VALUE(rv_recognized) TYPE abap_bool.
    METHODS unimplemented_reply
      IMPORTING
        io_packet       TYPE REF TO zcl_oassh_packet
      RETURNING
        VALUE(rv_reply) TYPE xstring.
    METHODS clear_credentials.
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
      iv_host   = iv_host
      iv_port   = iv_port
      iv_ssl_id = iv_ssl_id ).

    ro_ssh = NEW #(
      ii_socket            = li_socket
      ii_random            = li_random
      ii_host_verifier     = ii_host_verifier
      iv_host              = iv_host
      iv_port              = iv_port
      iv_user              = iv_user
      iv_password          = iv_password
      iv_password_supplied = xsdbool( iv_password IS SUPPLIED )
      iv_private_seed      = iv_private_seed ).

    li_socket->connect( ).
    ro_ssh->send_version( ).

  ENDMETHOD.


  METHOD execute.
* pump( ) drives authentication with inbound bytes as they arrive. Once the
* transport authenticates, start_channel sends CHANNEL_OPEN and the pump
* drives the channel until the peer closes it.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-execute.
    mv_command = iv_command.
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
* A socket error or SSH disconnect can complete the wait before a channel is
* opened or closed. Report that as a typed operation failure, never ASSERT.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    rv_output = zcl_oassh_ascii=>from_xstring_text( mo_channel->get_stdout( ) ).
  ENDMETHOD.


  METHOD shell.
* RFC 4254 sections 6.2 and 6.5: allocate a PTY, start the default shell,
* transfer byte-safe stdin under channel flow control, then half-close with
* CHANNEL_EOF while retaining all output until the peer closes the channel.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF iv_columns < 0 OR iv_rows < 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-shell.
    mv_shell_terminal = iv_terminal.
    mv_shell_columns = iv_columns.
    mv_shell_rows = iv_rows.
    mv_shell_input = iv_input.
    CLEAR mv_shell_offset.
    CLEAR mv_shell_eof_sent.
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND
        OR mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    rv_output = mo_channel->get_stdout( ).
  ENDMETHOD.


  METHOD exec_open.
* Interactive variant of execute( ): authenticate, open the session channel
* and start the command, then return control to the caller while the channel
* stays open for exec_write( ) / exec_read( ) exchanges.
    DATA lv_data TYPE xstring.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-exec_stream.
    mv_command = iv_command.
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
* pump( ) runs until the whole operation completes; this operation must stop
* as soon as the exec request is accepted, so drive the socket directly.
    WHILE mv_operation_done = abap_false
        AND ( mo_channel IS NOT BOUND
          OR mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-running ).
      lv_data = mi_socket->read( iv_timeout_seconds ).
      IF lv_data IS NOT INITIAL.
        process_inbound( lv_data ).
      ELSEIF mi_socket->is_closed( ) = abap_true.
        mv_operation_done = abap_true.
      ELSE.
        mi_socket->close( ).
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
    ENDWHILE.
* A disconnect or socket close before the command is running makes the
* interactive operation impossible.
    IF mv_operation_done = abap_true
        OR mo_channel IS NOT BOUND
        OR mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-running.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
  ENDMETHOD.


  METHOD exec_write.
* Queue stdin bytes for the running command and send what the remote window
* allows. Bytes that do not fit are sent when WINDOW_ADJUST arrives during a
* later exec_read( ) or exec_close( ).
    IF mv_operation <> gc_operation-exec_stream
        OR mo_channel IS NOT BOUND
        OR mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-running.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_data IS INITIAL.
      RETURN.
    ENDIF.
    CONCATENATE mv_exec_outbound iv_data INTO mv_exec_outbound IN BYTE MODE.
    flush_exec_output( ).
  ENDMETHOD.


  METHOD exec_read.
* Returns the stdout bytes buffered since the previous call and reads from
* the socket only when nothing is buffered. Mirrors zif_oassh_socket~read:
* an empty result is a timeout while exec_is_closed( ) is abap_false,
* otherwise the command's output stream has ended.
    DATA lv_data TYPE xstring.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mv_operation <> gc_operation-exec_stream OR mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    rv_data = mo_channel->drain_stdout( ).
    WHILE rv_data IS INITIAL AND exec_is_closed( ) = abap_false.
      lv_data = mi_socket->read( iv_timeout_seconds ).
      IF lv_data IS NOT INITIAL.
        process_inbound( lv_data ).
        rv_data = mo_channel->drain_stdout( ).
      ELSEIF mi_socket->is_closed( ) = abap_true.
        mv_operation_done = abap_true.
      ELSE.
        RETURN.
      ENDIF.
    ENDWHILE.
  ENDMETHOD.


  METHOD exec_eof.
* Half-close: signal end of stdin while the command's output continues.
* Stdin still queued behind a closed window would be silently dropped by the
* half-close, so flushing must have completed first.
    IF mv_operation <> gc_operation-exec_stream
        OR mo_channel IS NOT BOUND
        OR mv_exec_outbound IS NOT INITIAL.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    send_encrypted( mo_channel->eof( ) ).
  ENDMETHOD.


  METHOD exec_close.
* End the conversation: send CHANNEL_CLOSE and wait for the peer's CLOSE.
* The exit status is available through get_exit_status( ) afterwards.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mv_operation <> gc_operation-exec_stream OR mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) = zcl_oassh_channel=>c_state-closed.
      mv_operation_done = abap_true.
    ELSEIF mv_operation_done = abap_false
        AND mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-close_sent.
      send_encrypted( mo_channel->close( ) ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
  ENDMETHOD.


  METHOD exec_is_closed.
* No further stdout can arrive: the SSH connection ended, or the peer sent
* CHANNEL_EOF/CLOSE for the session channel.
    IF mv_operation_done = abap_true.
      rv_closed = abap_true.
      RETURN.
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RETURN.
    ENDIF.
    CASE mo_channel->get_state( ).
      WHEN zcl_oassh_channel=>c_state-eof_received
          OR zcl_oassh_channel=>c_state-close_sent
          OR zcl_oassh_channel=>c_state-closed.
        rv_closed = abap_true.
    ENDCASE.
  ENDMETHOD.


  METHOD sftp_open.
* Bring up a reusable SFTP session: authenticate, open the session channel,
* start the sftp subsystem and complete the INIT/VERSION handshake, then
* return with the channel held open. advance_channel drives the session case
* and never auto-closes the channel. Mirrors exec_open( )'s drive loop shape.
    DATA lv_data TYPE xstring.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_session.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    WHILE mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-ready
        AND mv_operation_done = abap_false.
      lv_data = mi_socket->read( iv_timeout_seconds ).
      IF lv_data IS NOT INITIAL.
        process_inbound( lv_data ).
      ELSEIF mi_socket->is_closed( ) = abap_true.
        mv_operation_done = abap_true.
      ELSE.
        mi_socket->close( ).
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
    ENDWHILE.
* A disconnect or socket close before VERSION makes the session impossible.
    IF mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-ready
        OR mo_channel IS NOT BOUND
        OR mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-running.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    mv_sftp_session = abap_true.
  ENDMETHOD.


  METHOD sftp_close.
* End the SFTP session: send CHANNEL_CLOSE and wait for the peer's CLOSE, the
* same handshake as exec_close( ). close( ) on the socket stays separate.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mv_sftp_session = abap_false OR mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    mv_sftp_session = abap_false.
    IF mo_channel->get_state( ) = zcl_oassh_channel=>c_state-closed.
      mv_operation_done = abap_true.
    ELSEIF mv_operation_done = abap_false
        AND mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-close_sent.
      send_encrypted( mo_channel->close( ) ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
  ENDMETHOD.


  METHOD pump_sftp_session.
* Drive the socket until the current SFTP operation reaches finished. Unlike
* pump( ), the session channel stays open across operations, so completion is
* the SFTP protocol finishing, not the SSH channel closing. A read timeout
* leaves mo_sftp unfinished and returns so the caller reports it.
    DATA lv_data TYPE xstring.
    WHILE mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished
        AND mv_operation_done = abap_false.
      lv_data = mi_socket->read( iv_timeout_seconds ).
      IF lv_data IS NOT INITIAL.
        process_inbound( lv_data ).
      ELSEIF mi_socket->is_closed( ) = abap_true.
        mv_operation_done = abap_true.
      ELSE.
        RETURN.
      ENDIF.
    ENDWHILE.
  ENDMETHOD.


  METHOD sftp_session_run.
* Run one operation inside an open session: send its first request, pump until
* the SFTP layer finishes, then validate the transport position. A clean
* finish (including an SFTP status error) leaves the session usable. A timeout
* or transport/protocol error leaves the protocol position undefined, so the
* session is marked broken and only close( ) remains valid afterwards.
    queue_sftp_output( iv_request ).
    flush_sftp_output( ).
    pump_sftp_session( iv_timeout_seconds ).
    IF mo_channel IS BOUND
        AND mo_channel->get_state( ) = zcl_oassh_channel=>c_state-running
        AND mo_sftp->get_state( ) = zcl_oassh_sftp=>c_state-finished.
      RETURN.
    ENDIF.
    mv_sftp_session_broken = abap_true.
    IF mv_operation_done = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
  ENDMETHOD.


  METHOD sftp_download.
* The public operation remains binary-safe end to end. Authentication and
* channel setup share the execute callback flow; only the channel operation
* selected after open differs.
    DATA lv_status TYPE i.
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      sftp_session_run(
        iv_request         = mo_sftp->start_download( iv_path )
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      rv_data = mo_sftp->get_data( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_download.
    mv_sftp_path = iv_path.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
    ENDIF.
    rv_data = mo_sftp->get_data( ).
  ENDMETHOD.


  METHOD sftp_upload.
* Upload completion means every WRITE was acknowledged and the remote handle
* and SSH channel both completed their close handshakes.
    DATA lv_status TYPE i.
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      sftp_session_run(
        iv_request         = mo_sftp->start_upload(
                               iv_path = iv_path
                               iv_data = iv_data )
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_upload.
    mv_sftp_path = iv_path.
    mv_sftp_upload_data = iv_data.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
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
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      sftp_session_run(
        iv_request         = mo_sftp->start_stat(
                               iv_path  = iv_path
                               iv_lstat = iv_lstat )
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      rs_attrs = mo_sftp->get_attrs( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
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
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
    ENDIF.
    rs_attrs = mo_sftp->get_attrs( ).
  ENDMETHOD.


  METHOD sftp_list.
    DATA lv_status TYPE i.
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      sftp_session_run(
        iv_request         = mo_sftp->start_list( iv_path )
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      rt_names = mo_sftp->get_names( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_list.
    mv_sftp_path = iv_path.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
    ENDIF.
    rt_names = mo_sftp->get_names( ).
  ENDMETHOD.


  METHOD sftp_mkdir.
    sftp_mutation(
      iv_operation       = gc_operation-sftp_mkdir
      iv_path            = iv_path
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_rmdir.
    sftp_mutation(
      iv_operation       = gc_operation-sftp_rmdir
      iv_path            = iv_path
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_remove.
    sftp_mutation(
      iv_operation       = gc_operation-sftp_remove
      iv_path            = iv_path
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_rename.
    sftp_mutation(
      iv_operation       = gc_operation-sftp_rename
      iv_path            = iv_old_path
      iv_path2           = iv_new_path
      iv_timeout_seconds = iv_timeout_seconds ).
  ENDMETHOD.


  METHOD sftp_mutation.
    DATA lv_status TYPE i.
    DATA lv_request TYPE xstring.
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      CASE iv_operation.
        WHEN gc_operation-sftp_mkdir.
          lv_request = mo_sftp->start_mkdir( iv_path ).
        WHEN gc_operation-sftp_rmdir.
          lv_request = mo_sftp->start_rmdir( iv_path ).
        WHEN gc_operation-sftp_remove.
          lv_request = mo_sftp->start_remove( iv_path ).
        WHEN gc_operation-sftp_rename.
          lv_request = mo_sftp->start_rename(
            iv_old_path = iv_path
            iv_new_path = iv_path2 ).
        WHEN OTHERS.
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDCASE.
      sftp_session_run(
        iv_request         = lv_request
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = iv_operation.
    mv_sftp_path = iv_path.
    mv_sftp_path2 = iv_path2.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
    ENDIF.
  ENDMETHOD.


  METHOD sftp_realpath.
    DATA lv_status TYPE i.
    IF mv_sftp_session = abap_true.
      IF mv_sftp_session_broken = abap_true.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
      ENDIF.
      IF iv_timeout_seconds <= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      ENDIF.
      sftp_session_run(
        iv_request         = mo_sftp->start_realpath( iv_path )
        iv_timeout_seconds = iv_timeout_seconds ).
      lv_status = mo_sftp->get_error_status( ).
      rs_name = mo_sftp->get_realpath( ).
      mo_sftp->continue_session( ).
      IF lv_status >= 0.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH |{ lv_status }|
          EXPORTING
            iv_sftp_status = lv_status.
      ENDIF.
      RETURN.
    ENDIF.
    IF mv_operation_started = abap_true.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF iv_timeout_seconds <= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    mv_operation_started = abap_true.
    mv_operation = gc_operation-sftp_realpath.
    mv_sftp_path = iv_path.
    mo_sftp = NEW #( ).
    IF mo_transport->get_auth_state( ) = zcl_oassh_transport=>c_auth_state-authenticated.
      start_channel( ).
    ENDIF.
    pump( iv_timeout_seconds ).
    IF mv_operation_done <> abap_true.
      mi_socket->close( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
    ENDIF.
    IF mo_channel IS NOT BOUND.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    IF mo_channel->get_state( ) <> zcl_oassh_channel=>c_state-closed
        OR mo_sftp->get_state( ) <> zcl_oassh_sftp=>c_state-finished.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
    ENDIF.
    lv_status = mo_sftp->get_error_status( ).
    IF lv_status >= 0.
      RAISE EXCEPTION TYPE zcx_oassh_error
        MESSAGE e012(zoassh) WITH |{ lv_status }|
        EXPORTING
          iv_sftp_status = lv_status.
    ENDIF.
    rs_name = mo_sftp->get_realpath( ).
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
    clear_credentials( ).
    IF mo_transport IS BOUND.
      mo_transport->clear_secrets( ).
    ENDIF.
    IF mo_plain_packet IS BOUND.
      mo_plain_packet->clear_secrets( ).
    ENDIF.
    mi_socket->close( ).
  ENDMETHOD.


  METHOD clear_credentials.
    CLEAR mv_password.
    CLEAR mv_password_supplied.
    CLEAR mv_private_seed.
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
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF rv_handled = abap_true
        AND iv_payload(1) = zcl_oassh_message_1=>gc_message_id.
      mv_disconnected = abap_true.
      mv_disconnect_reason = ls_disconnect-reason_code.
      mv_operation_done = abap_true.
      clear_credentials( ).
      IF mo_transport IS BOUND.
        mo_transport->clear_secrets( ).
      ENDIF.
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
      ii_host_verifier = ii_host_verifier
      iv_host          = iv_host
      iv_port          = iv_port ).
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
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
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
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
* RFC 4253 permits diagnostic lines but gives them no size limit. Bound an
* unterminated/non-SSH line at the transport ceiling to prevent unbounded
* pre-authentication buffering.
      IF lv_version_length > lc_max_prebanner.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
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
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    lv_last_offset = xstrlen( iv_identification ) - 1.
    DO xstrlen( iv_identification ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte = iv_identification+lv_offset(1).
      IF lv_byte = '00'.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      IF lv_offset < 8 OR lv_comment_started = abap_true.
        CONTINUE.
      ENDIF.
      IF lv_byte = '20'.
        IF lv_software_length = 0
            OR lv_offset = lv_last_offset.
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
        ENDIF.
        lv_comment_started = abap_true.
        CONTINUE.
      ENDIF.
      lv_code = lv_byte.
      IF lv_code < 33 OR lv_code > 126 OR lv_byte = '2D'.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_software_length = lv_software_length + 1.
    ENDDO.
    IF lv_software_length = 0.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
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
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
        ENDIF.
        IF mv_plain_packet_length > lv_max_length.
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
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
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
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
            RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
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
          TRY.
              lv_reply = mo_transport->start_auth(
                iv_user              = mv_user
                iv_password          = mv_password
                iv_password_supplied = mv_password_supplied
                iv_private_seed      = mv_private_seed ).
            CLEANUP.
              clear_credentials( ).
          ENDTRY.
          clear_credentials( ).
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
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
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
          WHEN gc_operation-execute OR gc_operation-exec_stream.
            lv_reply = mo_channel->exec( mv_command ).
          WHEN gc_operation-shell.
            lv_reply = mo_channel->pty(
              iv_terminal = mv_shell_terminal
              iv_columns  = mv_shell_columns
              iv_rows     = mv_shell_rows ).
          WHEN gc_operation-sftp_download OR gc_operation-sftp_upload
              OR gc_operation-sftp_stat OR gc_operation-sftp_lstat
              OR gc_operation-sftp_list OR gc_operation-sftp_mkdir
              OR gc_operation-sftp_rmdir OR gc_operation-sftp_remove
              OR gc_operation-sftp_rename OR gc_operation-sftp_realpath
              OR gc_operation-sftp_session.
            lv_reply = mo_channel->subsystem( 'sftp' ).
          WHEN OTHERS.
            RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
        ENDCASE.
        send_encrypted( lv_reply ).
      WHEN zcl_oassh_channel=>c_state-pty_ready.
        IF mv_operation <> gc_operation-shell.
          RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e010(zoassh).
        ENDIF.
        send_encrypted( mo_channel->shell( ) ).
      WHEN zcl_oassh_channel=>c_state-running.
        CASE mv_operation.
          WHEN gc_operation-shell.
            flush_shell_input( ).
          WHEN gc_operation-exec_stream.
* Stdout stays buffered in the channel until the caller's next exec_read( );
* only stdin blocked on window credit is progressed here.
            flush_exec_output( ).
          WHEN gc_operation-sftp_download OR gc_operation-sftp_upload
              OR gc_operation-sftp_stat OR gc_operation-sftp_lstat
              OR gc_operation-sftp_list OR gc_operation-sftp_mkdir
              OR gc_operation-sftp_rmdir OR gc_operation-sftp_remove
              OR gc_operation-sftp_rename OR gc_operation-sftp_realpath.
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
                WHEN gc_operation-sftp_list.
                  lv_sftp_output = mo_sftp->start_list( mv_sftp_path ).
                WHEN gc_operation-sftp_mkdir.
                  lv_sftp_output = mo_sftp->start_mkdir( mv_sftp_path ).
                WHEN gc_operation-sftp_rmdir.
                  lv_sftp_output = mo_sftp->start_rmdir( mv_sftp_path ).
                WHEN gc_operation-sftp_remove.
                  lv_sftp_output = mo_sftp->start_remove( mv_sftp_path ).
                WHEN gc_operation-sftp_rename.
                  lv_sftp_output = mo_sftp->start_rename(
                    iv_old_path = mv_sftp_path
                    iv_new_path = mv_sftp_path2 ).
                WHEN gc_operation-sftp_realpath.
                  lv_sftp_output = mo_sftp->start_realpath( mv_sftp_path ).
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
          WHEN gc_operation-sftp_session.
* Multi-operation session: send INIT once the subsystem is running, then feed
* every CHANNEL_DATA batch to the shared mo_sftp and flush its replies. The
* channel is never auto-closed here; sftp_close( ) ends the session.
            flush_sftp_output( ).
            IF mo_sftp->get_state( ) = zcl_oassh_sftp=>c_state-created.
              lv_sftp_output = mo_sftp->start( ).
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
        ENDCASE.
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


  METHOD flush_exec_output.
* Same window discipline as flush_sftp_output, for the interactive exec
* stdin queue. WINDOW_ADJUST callbacks re-enter this method through
* advance_channel while the channel is running.
    DATA lv_capacity TYPE i.
    DATA lv_pending_length TYPE i.
    DATA lv_send_length TYPE i.
    DATA lv_payload TYPE xstring.
    DATA lv_remainder TYPE xstring.
    DATA lv_reply TYPE xstring.
    lv_capacity = mo_channel->get_send_capacity( ).
    WHILE mv_exec_outbound IS NOT INITIAL AND lv_capacity > 0.
      lv_pending_length = xstrlen( mv_exec_outbound ).
      lv_send_length = lv_pending_length.
      IF lv_send_length > lv_capacity.
        lv_send_length = lv_capacity.
      ENDIF.
      lv_payload = mv_exec_outbound(lv_send_length).
      IF lv_send_length = lv_pending_length.
        CLEAR mv_exec_outbound.
      ELSE.
        lv_remainder = mv_exec_outbound+lv_send_length.
        mv_exec_outbound = lv_remainder.
      ENDIF.
      lv_reply = mo_channel->data( lv_payload ).
      send_encrypted( lv_reply ).
      lv_capacity = mo_channel->get_send_capacity( ).
    ENDWHILE.
  ENDMETHOD.


  METHOD flush_shell_input.
* Split stdin by both the peer's uint32 window and maximum packet size. EOF
* does not consume window credit and is sent exactly once after all input.
    DATA lv_capacity TYPE i.
    DATA lv_input_length TYPE i.
    DATA lv_pending_length TYPE i.
    DATA lv_send_length TYPE i.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    lv_input_length = xstrlen( mv_shell_input ).
    lv_capacity = mo_channel->get_send_capacity( ).
    WHILE mv_shell_offset < lv_input_length AND lv_capacity > 0.
      lv_pending_length = lv_input_length - mv_shell_offset.
      lv_send_length = lv_pending_length.
      IF lv_send_length > lv_capacity.
        lv_send_length = lv_capacity.
      ENDIF.
      lv_payload = mv_shell_input+mv_shell_offset(lv_send_length).
      lv_reply = mo_channel->data( lv_payload ).
      send_encrypted( lv_reply ).
      mv_shell_offset = mv_shell_offset + lv_send_length.
      lv_capacity = mo_channel->get_send_capacity( ).
    ENDWHILE.
    IF mv_shell_offset >= lv_input_length AND mv_shell_eof_sent = abap_false.
      CLEAR mv_shell_input.
      lv_reply = mo_channel->eof( ).
      send_encrypted( lv_reply ).
      mv_shell_eof_sent = abap_true.
    ENDIF.
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


  METHOD pump.
* drives the protocol: read( ) blocks until the server sends data, the
* timeout expires (empty result) or the transport closes. A transport close
* before SSH channel completion makes the active operation impossible; the
* caller reports it as a typed channel failure. On a read timeout
* mv_operation_done stays false and the caller reports a timeout.
    DATA lv_data TYPE xstring.
    WHILE mv_operation_done = abap_false.
      lv_data = mi_socket->read( iv_timeout_seconds ).
      IF lv_data IS NOT INITIAL.
        process_inbound( lv_data ).
      ELSEIF mi_socket->is_closed( ) = abap_true.
        mv_operation_done = abap_true.
      ELSE.
        RETURN.
      ENDIF.
    ENDWHILE.
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
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
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


  METHOD process_inbound.
* RFC 4253 section 11.1 forbids accepting data after DISCONNECT. A socket
* adapter may still have buffered bytes that arrived before the close.
    IF mv_disconnected = abap_true.
      RETURN.
    ENDIF.
    mo_stream->append( iv_data ).
    handle( ).
  ENDMETHOD.


  METHOD send_version.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    DATA lv_xstr TYPE xstring.
    mv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ). "#EC NOTEXT
    lv_xstr = mv_client_version && zcl_oassh_ascii=>c_cr_lf.

    mi_socket->send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.
ENDCLASS.
