CLASS zcl_oassh_channel DEFINITION
  PUBLIC FINAL CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS:
      BEGIN OF c_state,
        initial       TYPE i VALUE 0,
        open_sent     TYPE i VALUE 1,
        open          TYPE i VALUE 2,
        exec_sent     TYPE i VALUE 3,
        running       TYPE i VALUE 4,
        eof_received  TYPE i VALUE 5,
        closed        TYPE i VALUE 6,
      END OF c_state.
    METHODS open RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS exec
      IMPORTING iv_command TYPE string
      RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS receive
      IMPORTING iv_payload TYPE xstring
      RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS get_state RETURNING VALUE(rv_state) TYPE i.
    METHODS get_stdout RETURNING VALUE(rv_data) TYPE xstring.
    METHODS get_stderr RETURNING VALUE(rv_data) TYPE xstring.
    METHODS get_exit_status RETURNING VALUE(rv_status) TYPE i.

  PRIVATE SECTION.
    CONSTANTS c_local_channel TYPE i VALUE 0.
    CONSTANTS c_window_size TYPE i VALUE 1048576.
    CONSTANTS c_max_packet TYPE i VALUE 32768.
    DATA mv_state TYPE i.
    DATA mv_remote_channel TYPE i.
    DATA mv_remote_window TYPE i.
    DATA mv_remote_max_packet TYPE i.
    DATA mv_local_window TYPE i VALUE c_window_size.
    DATA mv_stdout TYPE xstring.
    DATA mv_stderr TYPE xstring.
    DATA mv_exit_status TYPE i VALUE -1.
ENDCLASS.

CLASS zcl_oassh_channel IMPLEMENTATION.
  METHOD open.
* SSH_MSG_CHANNEL_OPEN, RFC 4254 section 5.1
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ASSERT mv_state = c_state-initial.
    lo_stream = NEW #( ).
    lo_stream->append( '5A' ). " 90
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'session' ) ).
    lo_stream->uint32_encode( c_local_channel ).
    lo_stream->uint32_encode( c_window_size ).
    lo_stream->uint32_encode( c_max_packet ).
    rv_payload = lo_stream->get( ).
    mv_state = c_state-open_sent.
  ENDMETHOD.

  METHOD exec.
* SSH_MSG_CHANNEL_REQUEST "exec", RFC 4254 section 6.5
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ASSERT mv_state = c_state-open.
    lo_stream = NEW #( ).
    lo_stream->append( '62' ). " 98
    lo_stream->uint32_encode( mv_remote_channel ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'exec' ) ).
    lo_stream->boolean_encode( abap_true ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( iv_command ) ).
    rv_payload = lo_stream->get( ).
    mv_state = c_state-exec_sent.
  ENDMETHOD.

  METHOD receive.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lo_reply TYPE REF TO zcl_oassh_stream.
    DATA lv_id TYPE x LENGTH 1.
    DATA lv_recipient TYPE i.
    DATA lv_data TYPE xstring.
    DATA lv_type TYPE i.
    DATA lv_request TYPE xstring.
    DATA lv_want_reply TYPE abap_bool.
    lo_stream = NEW #( iv_payload ).
    lv_id = lo_stream->take( 1 ).
    CASE lv_id.
      WHEN '5B'. " CHANNEL_OPEN_CONFIRMATION (91)
        ASSERT mv_state = c_state-open_sent.
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        mv_remote_channel = lo_stream->uint32_decode( ).
        mv_remote_window = lo_stream->uint32_decode( ).
        mv_remote_max_packet = lo_stream->uint32_decode( ).
        mv_state = c_state-open.
      WHEN '5D'. " WINDOW_ADJUST (93)
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        mv_remote_window = mv_remote_window + lo_stream->uint32_decode( ).
      WHEN '5E'. " DATA (94)
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        lv_data = lo_stream->string_decode( ).
        CONCATENATE mv_stdout lv_data INTO mv_stdout IN BYTE MODE.
        mv_local_window = mv_local_window - xstrlen( lv_data ).
      WHEN '5F'. " EXTENDED_DATA (95), type 1 is stderr
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        lv_type = lo_stream->uint32_decode( ).
        lv_data = lo_stream->string_decode( ).
        IF lv_type = 1.
          CONCATENATE mv_stderr lv_data INTO mv_stderr IN BYTE MODE.
        ENDIF.
        mv_local_window = mv_local_window - xstrlen( lv_data ).
      WHEN '63'. " CHANNEL_SUCCESS (99)
        ASSERT mv_state = c_state-exec_sent.
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        mv_state = c_state-running.
      WHEN '64'. " CHANNEL_FAILURE (100)
        ASSERT 1 = 2.
      WHEN '62'. " server channel request: exit-status
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        lv_request = lo_stream->string_decode( ).
        lv_want_reply = lo_stream->boolean_decode( ).
        IF zcl_oassh_ascii=>from_xstring( lv_request ) = 'exit-status'.
          mv_exit_status = lo_stream->uint32_decode( ).
        ENDIF.
      WHEN '60'. " EOF (96)
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        mv_state = c_state-eof_received.
      WHEN '61'. " CLOSE (97): echo CLOSE exactly once
        lv_recipient = lo_stream->uint32_decode( ).
        ASSERT lv_recipient = c_local_channel.
        lo_reply = NEW #( ).
        lo_reply->append( '61' ).
        lo_reply->uint32_encode( mv_remote_channel ).
        rv_payload = lo_reply->get( ).
        mv_state = c_state-closed.
      WHEN OTHERS.
        ASSERT 1 = 2.
    ENDCASE.
    ASSERT lo_stream->get_length( ) = 0.
  ENDMETHOD.

  METHOD get_state.
    rv_state = mv_state.
  ENDMETHOD.


  METHOD get_stdout.
    rv_data = mv_stdout.
  ENDMETHOD.


  METHOD get_stderr.
    rv_data = mv_stderr.
  ENDMETHOD.


  METHOD get_exit_status.
    rv_status = mv_exit_status.
  ENDMETHOD.
ENDCLASS.
