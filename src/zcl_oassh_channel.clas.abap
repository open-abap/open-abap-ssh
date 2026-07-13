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
        close_sent    TYPE i VALUE 6,
        closed        TYPE i VALUE 7,
      END OF c_state.
    METHODS open RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS exec
      IMPORTING iv_command TYPE string
      RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS subsystem
      IMPORTING iv_name TYPE string
      RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS data
      IMPORTING iv_data TYPE xstring
      RETURNING VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS close
      RETURNING VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS receive
      IMPORTING iv_payload TYPE xstring
      RETURNING VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS get_state RETURNING VALUE(rv_state) TYPE i.
    METHODS get_stdout RETURNING VALUE(rv_data) TYPE xstring.
    METHODS drain_stdout RETURNING VALUE(rv_data) TYPE xstring.
    METHODS get_stderr RETURNING VALUE(rv_data) TYPE xstring.
    METHODS get_exit_status RETURNING VALUE(rv_status) TYPE i.

  PRIVATE SECTION.
    TYPES ty_uint32 TYPE x LENGTH 4.
    CONSTANTS c_local_channel TYPE i VALUE 0.
    CONSTANTS c_window_size TYPE i VALUE 1048576.
    CONSTANTS c_max_packet TYPE i VALUE 32768.
    DATA mv_state TYPE i.
    DATA mv_remote_channel TYPE i.
    DATA mv_remote_window TYPE ty_uint32.
    DATA mv_remote_max_packet TYPE ty_uint32.
    DATA mv_local_window TYPE i VALUE c_window_size.
    TYPES ty_chunks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    DATA mt_stdout TYPE ty_chunks.
    DATA mt_stderr TYPE ty_chunks.
    DATA mv_exit_status TYPE i VALUE -1.
    METHODS read_recipient
      IMPORTING io_stream TYPE REF TO zcl_oassh_stream
      RETURNING VALUE(rv_recipient) TYPE i
      RAISING zcx_oassh_error.
    METHODS consume_local_window
      IMPORTING
        iv_length        TYPE i
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS ensure_channel_open
      RAISING zcx_oassh_error.
    METHODS ensure_consumed
      IMPORTING io_stream TYPE REF TO zcl_oassh_stream
      RAISING zcx_oassh_error.
    METHODS receive_open_confirmation
      IMPORTING io_stream TYPE REF TO zcl_oassh_stream
      RAISING zcx_oassh_error.
    METHODS receive_close
      IMPORTING
        io_stream        TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING
        zcx_oassh_error.
    CLASS-METHODS ensure_data_length
      IMPORTING iv_data TYPE xstring
      RAISING zcx_oassh_error.
    METHODS handle_server_request
      IMPORTING
        io_stream        TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING zcx_oassh_error.
    CLASS-METHODS add_uint32
      IMPORTING
        iv_left       TYPE ty_uint32
        iv_right      TYPE ty_uint32
      RETURNING
        VALUE(rv_sum) TYPE ty_uint32
      RAISING
        zcx_oassh_error.
    CLASS-METHODS subtract_uint32
      IMPORTING
        iv_left       TYPE ty_uint32
        iv_right      TYPE i
      RETURNING
        VALUE(rv_sum) TYPE ty_uint32
      RAISING
        zcx_oassh_error.
    CLASS-METHODS uint32_fits
      IMPORTING
        iv_available   TYPE ty_uint32
        iv_length      TYPE i
      RETURNING
        VALUE(rv_fits) TYPE abap_bool.
    CLASS-METHODS join_chunks
      IMPORTING
        it_chunks     TYPE ty_chunks
      RETURNING
        VALUE(rv_data) TYPE xstring.
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
* The exec command is application text, not an ASCII protocol identifier.
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring_text( iv_command ) ).
    rv_payload = lo_stream->get( ).
    mv_state = c_state-exec_sent.
  ENDMETHOD.

  METHOD subsystem.
* SSH_MSG_CHANNEL_REQUEST "subsystem", RFC 4254 section 6.5. This shares the
* exact request/reply cycle with exec (want_reply true, answered by
* CHANNEL_SUCCESS/FAILURE), so it reuses the exec_sent state and the existing
* reply handling in receive( ) unchanged. The subsystem name is an ASCII token.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ASSERT mv_state = c_state-open.
    lo_stream = NEW #( ).
    lo_stream->append( '62' ). " 98
    lo_stream->uint32_encode( mv_remote_channel ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'subsystem' ) ).
    lo_stream->boolean_encode( abap_true ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( iv_name ) ).
    rv_payload = lo_stream->get( ).
    mv_state = c_state-exec_sent.
  ENDMETHOD.


  METHOD data.
* RFC 4254 section 5.2: channel data consumes the peer's advertised window
* and may not exceed its maximum packet size.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    IF mv_state <> c_state-running.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    IF uint32_fits(
        iv_available = mv_remote_window
        iv_length    = xstrlen( iv_data ) ) = abap_false
        OR uint32_fits(
          iv_available = mv_remote_max_packet
          iv_length    = xstrlen( iv_data ) ) = abap_false.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lo_stream = NEW #( ).
    lo_stream->append( '5E' ).
    lo_stream->uint32_encode( mv_remote_channel ).
    lo_stream->string_encode( iv_data ).
    rv_payload = lo_stream->get( ).
    mv_remote_window = subtract_uint32(
      iv_left  = mv_remote_window
      iv_right = xstrlen( iv_data ) ).
  ENDMETHOD.


  METHOD close.
* RFC 4254 section 5.3 permits CLOSE without a preceding EOF. The peer must
* answer with CLOSE; receive( ) then publishes the terminal closed state.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    IF mv_state <> c_state-running AND mv_state <> c_state-eof_received.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lo_stream = NEW #( ).
    lo_stream->append( '61' ).
    lo_stream->uint32_encode( mv_remote_channel ).
    rv_payload = lo_stream->get( ).
    mv_state = c_state-close_sent.
  ENDMETHOD.

  METHOD receive.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_id TYPE x LENGTH 1.
    DATA lv_recipient TYPE i.
    DATA lv_data TYPE xstring.
    DATA lv_type TYPE i.
    DATA lv_uint32 TYPE ty_uint32.
    DATA lv_new_window TYPE ty_uint32.
    lo_stream = NEW #( iv_payload ).
    lv_id = lo_stream->take( 1 ).
    CASE lv_id.
      WHEN '5B'. " CHANNEL_OPEN_CONFIRMATION (91)
        receive_open_confirmation( lo_stream ).
      WHEN '5C'. " CHANNEL_OPEN_FAILURE (92)
        IF mv_state <> c_state-open_sent.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
* RFC 4254 section 5.1: reason, UTF-8 description, and language tag must all
* be consumed even though this API exposes only the typed channel failure.
        lv_uint32 = lo_stream->take( 4 ).
        lo_stream->string_decode( ).
        lo_stream->string_decode( ).
        ensure_consumed( lo_stream ).
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
      WHEN '5D'. " WINDOW_ADJUST (93)
        ensure_channel_open( ).
        lv_recipient = read_recipient( lo_stream ).
        lv_uint32 = lo_stream->take( 4 ).
        ensure_consumed( lo_stream ).
        lv_new_window = add_uint32(
          iv_left  = mv_remote_window
          iv_right = lv_uint32 ).
        mv_remote_window = lv_new_window.
      WHEN '5E'. " DATA (94)
        ensure_channel_open( ).
        IF mv_state = c_state-eof_received OR mv_state = c_state-close_sent.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
        lv_data = lo_stream->string_decode( ).
        ensure_consumed( lo_stream ).
        ensure_data_length( lv_data ).
        rv_payload = consume_local_window( xstrlen( lv_data ) ).
        IF lv_data IS NOT INITIAL.
          APPEND lv_data TO mt_stdout.
        ENDIF.
      WHEN '5F'. " EXTENDED_DATA (95), type 1 is stderr
        ensure_channel_open( ).
        IF mv_state = c_state-eof_received OR mv_state = c_state-close_sent.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
        lv_type = lo_stream->uint32_decode( ).
        lv_data = lo_stream->string_decode( ).
        ensure_consumed( lo_stream ).
        ensure_data_length( lv_data ).
        rv_payload = consume_local_window( xstrlen( lv_data ) ).
        IF lv_type = 1 AND lv_data IS NOT INITIAL.
          APPEND lv_data TO mt_stderr.
        ENDIF.
      WHEN '63'. " CHANNEL_SUCCESS (99)
        IF mv_state <> c_state-exec_sent.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
        ensure_consumed( lo_stream ).
        mv_state = c_state-running.
      WHEN '64'. " CHANNEL_FAILURE (100)
        IF mv_state <> c_state-exec_sent.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
        IF lo_stream->get_length( ) <> 0.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
      WHEN '62'. " server channel request: exit-status
        ensure_channel_open( ).
        rv_payload = handle_server_request( lo_stream ).
      WHEN '60'. " EOF (96)
        ensure_channel_open( ).
        IF mv_state = c_state-eof_received.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
        ENDIF.
        lv_recipient = read_recipient( lo_stream ).
        ensure_consumed( lo_stream ).
        IF mv_state <> c_state-close_sent.
          mv_state = c_state-eof_received.
        ENDIF.
      WHEN '61'. " CLOSE (97): echo CLOSE exactly once
        rv_payload = receive_close( lo_stream ).
      WHEN OTHERS.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDCASE.
    ensure_consumed( lo_stream ).
  ENDMETHOD.


  METHOD receive_open_confirmation.
    DATA lv_recipient TYPE i.
    DATA lv_remote_channel TYPE i.
    DATA lv_remote_window TYPE ty_uint32.
    DATA lv_remote_max_packet TYPE ty_uint32.
    IF mv_state <> c_state-open_sent.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_recipient = read_recipient( io_stream ).
    lv_remote_channel = io_stream->uint32_decode( ).
    lv_remote_window = io_stream->take( 4 ).
    lv_remote_max_packet = io_stream->take( 4 ).
    ensure_consumed( io_stream ).
    mv_remote_channel = lv_remote_channel.
    mv_remote_window = lv_remote_window.
    mv_remote_max_packet = lv_remote_max_packet.
    mv_state = c_state-open.
  ENDMETHOD.


  METHOD ensure_consumed.
    IF io_stream->get_length( ) <> 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD add_uint32.
* RFC 4254 section 5.2 requires windows through 2^32 - 1 and forbids
* overflow. Keep the value as four wire-order bytes because ABAP i is signed.
    DATA lv_offset TYPE i.
    DATA lv_left_byte TYPE x LENGTH 1.
    DATA lv_right_byte TYPE x LENGTH 1.
    DATA lv_result_byte TYPE x LENGTH 1.
    DATA lv_left TYPE i.
    DATA lv_right TYPE i.
    DATA lv_total TYPE i.
    DATA lv_carry TYPE i.
    rv_sum = iv_left.
    DO 4 TIMES.
      lv_offset = 4 - sy-index.
      lv_left_byte = iv_left+lv_offset(1).
      lv_right_byte = iv_right+lv_offset(1).
      lv_left = lv_left_byte.
      lv_right = lv_right_byte.
      lv_total = lv_left + lv_right + lv_carry.
      IF lv_total > 255.
        lv_total = lv_total - 256.
        lv_carry = 1.
      ELSE.
        CLEAR lv_carry.
      ENDIF.
      lv_result_byte = lv_total.
      rv_sum+lv_offset(1) = lv_result_byte.
    ENDDO.
    IF lv_carry <> 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD receive_close.
    DATA lo_reply TYPE REF TO zcl_oassh_stream.
    DATA lv_recipient TYPE i.
    ensure_channel_open( ).
    lv_recipient = read_recipient( io_stream ).
    ensure_consumed( io_stream ).
    IF mv_state <> c_state-close_sent.
      lo_reply = NEW #( ).
      lo_reply->append( '61' ).
      lo_reply->uint32_encode( mv_remote_channel ).
      rv_payload = lo_reply->get( ).
    ENDIF.
    mv_state = c_state-closed.
  ENDMETHOD.


  METHOD uint32_fits.
* Compare the four-byte unsigned value with a non-negative int4 without using
* ABAP's signed direct ordering for byte types.
    DATA lv_needed TYPE ty_uint32.
    DATA lv_offset TYPE i.
    DATA lv_available_byte TYPE x LENGTH 1.
    DATA lv_needed_byte TYPE x LENGTH 1.
    DATA lv_available TYPE i.
    DATA lv_required TYPE i.
    IF iv_length < 0.
      RETURN.
    ENDIF.
    lv_needed = iv_length.
    DO 4 TIMES.
      lv_offset = sy-index - 1.
      lv_available_byte = iv_available+lv_offset(1).
      lv_needed_byte = lv_needed+lv_offset(1).
      lv_available = lv_available_byte.
      lv_required = lv_needed_byte.
      IF lv_available > lv_required.
        rv_fits = abap_true.
        RETURN.
      ELSEIF lv_available < lv_required.
        RETURN.
      ENDIF.
    ENDDO.
    rv_fits = abap_true.
  ENDMETHOD.


  METHOD subtract_uint32.
    DATA lv_right TYPE ty_uint32.
    DATA lv_offset TYPE i.
    DATA lv_left_byte TYPE x LENGTH 1.
    DATA lv_right_byte TYPE x LENGTH 1.
    DATA lv_result_byte TYPE x LENGTH 1.
    DATA lv_left TYPE i.
    DATA lv_subtrahend TYPE i.
    DATA lv_total TYPE i.
    DATA lv_borrow TYPE i.
    IF uint32_fits(
        iv_available = iv_left
        iv_length    = iv_right ) = abap_false.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-channel_failed ).
    ENDIF.
    lv_right = iv_right.
    rv_sum = iv_left.
    DO 4 TIMES.
      lv_offset = 4 - sy-index.
      lv_left_byte = iv_left+lv_offset(1).
      lv_right_byte = lv_right+lv_offset(1).
      lv_left = lv_left_byte.
      lv_subtrahend = lv_right_byte + lv_borrow.
      IF lv_left < lv_subtrahend.
        lv_total = lv_left + 256 - lv_subtrahend.
        lv_borrow = 1.
      ELSE.
        lv_total = lv_left - lv_subtrahend.
        CLEAR lv_borrow.
      ENDIF.
      lv_result_byte = lv_total.
      rv_sum+lv_offset(1) = lv_result_byte.
    ENDDO.
  ENDMETHOD.


  METHOD handle_server_request.
    DATA lo_reply TYPE REF TO zcl_oassh_stream.
    DATA lv_recipient TYPE i.
    DATA lv_request TYPE xstring.
    DATA lv_exit_status TYPE xstring.
    DATA lv_want_reply TYPE abap_bool.
    DATA lv_recognized TYPE abap_bool.
    DATA lv_remaining TYPE i.
    lv_recipient = read_recipient( io_stream ).
    lv_request = io_stream->string_decode( ).
    lv_want_reply = io_stream->boolean_decode( ).
    lv_exit_status = zcl_oassh_ascii=>to_xstring( 'exit-status' ).
    IF lv_request = lv_exit_status.
      IF io_stream->get_length( ) <> 4.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      mv_exit_status = io_stream->uint32_decode( ).
      lv_recognized = abap_true.
    ELSE.
* Unknown request-specific data has no generic shape. RFC 4254 section 5.4
* requires it to be ignored and answered with CHANNEL_FAILURE when requested.
      lv_remaining = io_stream->get_length( ).
      io_stream->take( lv_remaining ).
    ENDIF.
    IF lv_want_reply = abap_true.
      lo_reply = NEW #( ).
      IF lv_recognized = abap_true.
        lo_reply->append( '63' ). " CHANNEL_SUCCESS (99)
      ELSE.
        lo_reply->append( '64' ). " CHANNEL_FAILURE (100)
      ENDIF.
      lo_reply->uint32_encode( mv_remote_channel ).
      rv_payload = lo_reply->get( ).
    ENDIF.
  ENDMETHOD.


  METHOD ensure_channel_open.
    IF mv_state < c_state-open OR mv_state = c_state-closed.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD ensure_data_length.
* RFC 4254 section 5.2: maximum packet size limits the data string for both
* ordinary and extended channel data, independent of their envelope sizes.
    IF xstrlen( iv_data ) > c_max_packet.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD consume_local_window.
* RFC 4254 sections 5.2 and 5.4: peers may not consume more than the
* advertised window. Restore it when half is consumed so large command output
* cannot stall waiting for credit that this client never returns.
    DATA lo_reply TYPE REF TO zcl_oassh_stream.
    DATA lv_adjust TYPE i.
    DATA lv_threshold TYPE i.
    IF iv_length > mv_local_window.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    mv_local_window = mv_local_window - iv_length.
    lv_threshold = c_window_size DIV 2.
    IF mv_local_window <= lv_threshold.
      lv_adjust = c_window_size - mv_local_window.
      lo_reply = NEW #( ).
      lo_reply->append( '5D' ).
      lo_reply->uint32_encode( mv_remote_channel ).
      lo_reply->uint32_encode( lv_adjust ).
      rv_payload = lo_reply->get( ).
      mv_local_window = c_window_size.
    ENDIF.
  ENDMETHOD.


  METHOD join_chunks.
* Pairwise joining bounds each byte to logarithmically many copies instead of
* repeatedly copying the complete output for every received packet.
    DATA lt_current TYPE ty_chunks.
    DATA lt_next TYPE ty_chunks.
    DATA lv_index TYPE i.
    DATA lv_count TYPE i.
    DATA lv_joined TYPE xstring.
    lt_current = it_chunks.
    WHILE lines( lt_current ) > 1.
      CLEAR lt_next.
      lv_index = 1.
      lv_count = lines( lt_current ).
      WHILE lv_index <= lv_count.
        IF lv_index = lv_count.
          APPEND lt_current[ lv_index ] TO lt_next.
        ELSE.
          CONCATENATE lt_current[ lv_index ] lt_current[ lv_index + 1 ]
            INTO lv_joined IN BYTE MODE.
          APPEND lv_joined TO lt_next.
        ENDIF.
        lv_index = lv_index + 2.
      ENDWHILE.
      lt_current = lt_next.
    ENDWHILE.
    IF lt_current IS NOT INITIAL.
      rv_data = lt_current[ 1 ].
    ENDIF.
  ENDMETHOD.


  METHOD read_recipient.
    rv_recipient = io_stream->uint32_decode( ).
    IF rv_recipient <> c_local_channel.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
  ENDMETHOD.

  METHOD get_state.
    rv_state = mv_state.
  ENDMETHOD.


  METHOD get_stdout.
    rv_data = join_chunks( mt_stdout ).
  ENDMETHOD.


  METHOD drain_stdout.
* Incremental inbound hand-off for owners that must react to CHANNEL_DATA while
* the channel is still open (e.g. the SFTP client reassembling its own framing),
* rather than reading everything once at close via get_stdout( ). Returns the
* bytes buffered since the previous drain and clears them, so a long transfer
* does not accumulate the whole stream in the channel. execute( ) never calls
* this, so its get_stdout( )-at-close behaviour is unchanged.
    rv_data = join_chunks( mt_stdout ).
    CLEAR mt_stdout.
  ENDMETHOD.


  METHOD get_stderr.
    rv_data = join_chunks( mt_stderr ).
  ENDMETHOD.


  METHOD get_exit_status.
    rv_status = mv_exit_status.
  ENDMETHOD.
ENDCLASS.
