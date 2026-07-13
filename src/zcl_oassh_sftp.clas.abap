CLASS zcl_oassh_sftp DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS c_max_packet_length TYPE i VALUE 262144.
    CONSTANTS:
      BEGIN OF c_state,
        created         TYPE i VALUE 0,
        version_pending TYPE i VALUE 1,
        ready           TYPE i VALUE 2,
        open_pending    TYPE i VALUE 3,
        read_pending    TYPE i VALUE 4,
        close_pending   TYPE i VALUE 5,
        write_pending   TYPE i VALUE 6,
        finished        TYPE i VALUE 7,
      END OF c_state.

    METHODS constructor.
    METHODS start
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS start_download
      IMPORTING
        iv_path        TYPE string
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS start_upload
      IMPORTING
        iv_path        TYPE string
        iv_data        TYPE xstring
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS receive
      IMPORTING
        iv_data TYPE xstring
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS get_state
      RETURNING
        VALUE(rv_state) TYPE i.
    METHODS get_version
      RETURNING
        VALUE(rv_version) TYPE i.
    METHODS get_data
      RETURNING
        VALUE(rv_data) TYPE xstring.
    METHODS get_error_status
      RETURNING
        VALUE(rv_status) TYPE i.

  PRIVATE SECTION.
    TYPES ty_request_ids TYPE SORTED TABLE OF i WITH UNIQUE KEY table_line.
    TYPES ty_chunks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    CONSTANTS c_operation_download TYPE i VALUE 1.
    CONSTANTS c_operation_upload TYPE i VALUE 2.
    CONSTANTS c_read_length TYPE i VALUE 32768.

    DATA mo_receive TYPE REF TO zcl_oassh_stream.
    DATA mv_expected_length TYPE i.
    DATA mv_state TYPE i.
    DATA mv_version TYPE i.
    DATA mv_next_request_id TYPE i VALUE 1.
    DATA mt_request_ids TYPE ty_request_ids.
    DATA mv_response_count TYPE i.
    DATA mv_last_response_type TYPE zcl_oassh_stream=>ty_byte.
    DATA mv_last_response_body TYPE xstring.
    DATA mv_operation TYPE i.
    DATA mv_path TYPE xstring.
    DATA mv_handle TYPE xstring.
    DATA mv_offset TYPE i.
    DATA mt_data TYPE ty_chunks.
    DATA mv_error_status TYPE i VALUE -1.
    DATA mv_outbound TYPE xstring.
    DATA mv_upload_data TYPE xstring.
    DATA mv_upload_position TYPE i.
    DATA mv_write_length TYPE i.

    METHODS frame
      IMPORTING
        iv_type        TYPE zcl_oassh_stream=>ty_byte
        iv_body        TYPE xstring
      RETURNING
        VALUE(rv_data) TYPE xstring.
    METHODS build_request
      IMPORTING
        iv_type        TYPE zcl_oassh_stream=>ty_byte
        iv_body        TYPE xstring
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS next_request_id
      RETURNING
        VALUE(rv_id) TYPE i
      RAISING
        zcx_oassh_error.
    METHODS handle_packet
      IMPORTING
        iv_packet TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS handle_version
      IMPORTING
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    METHODS handle_response
      IMPORTING
        iv_type   TYPE zcl_oassh_stream=>ty_byte
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    METHODS handle_download_response
      IMPORTING
        iv_type   TYPE zcl_oassh_stream=>ty_byte
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    METHODS handle_write_response
      IMPORTING
        iv_type   TYPE x
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    METHODS open_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS read_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS close_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS write_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    CLASS-METHODS parse_status
      IMPORTING
        io_packet       TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rv_status) TYPE i
      RAISING
        zcx_oassh_error.
    CLASS-METHODS ensure_consumed
      IMPORTING
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    CLASS-METHODS join_chunks
      IMPORTING
        it_chunks     TYPE ty_chunks
      RETURNING
        VALUE(rv_data) TYPE xstring.
ENDCLASS.


CLASS zcl_oassh_sftp IMPLEMENTATION.

  METHOD constructor.
    mo_receive = NEW #( ).
  ENDMETHOD.


  METHOD start.
* draft-ietf-secsh-filexfer-02 section 4: INIT has no request id and carries
* the protocol version as its complete data payload.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    lo_body = NEW #( ).
    lo_body->uint32_encode( 3 ).
    rv_data = frame(
      iv_type = '01'
      iv_body = lo_body->get( ) ).
    mv_state = c_state-version_pending.
  ENDMETHOD.


  METHOD start_download.
* Version 3 file names are UTF-8 strings. The operation begins with INIT; OPEN
* is emitted only after the server confirms VERSION 3.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    mv_operation = c_operation_download.
    mv_path = zcl_oassh_ascii=>to_xstring_text( iv_path ).
    rv_data = start( ).
  ENDMETHOD.


  METHOD start_upload.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    mv_operation = c_operation_upload.
    mv_path = zcl_oassh_ascii=>to_xstring_text( iv_path ).
    mv_upload_data = iv_data.
    rv_data = start( ).
  ENDMETHOD.


  METHOD receive.
* SFTP framing is independent of SSH CHANNEL_DATA boundaries. Keep incomplete
* bytes in the chunked stream and dispatch every complete packet in order.
    DATA lv_length TYPE i.
    DATA lv_packet TYPE xstring.
    mo_receive->append( iv_data ).
    WHILE mo_receive->get_length( ) >= 4.
      IF mv_expected_length = 0.
        lv_length = mo_receive->uint32_decode_peek( ).
        IF lv_length < 1 OR lv_length > c_max_packet_length.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDIF.
        mv_expected_length = lv_length.
      ENDIF.
      IF mo_receive->get_length( ) < mv_expected_length + 4.
        RETURN.
      ENDIF.
      mo_receive->take( 4 ).
      lv_packet = mo_receive->take( mv_expected_length ).
      CLEAR mv_expected_length.
      handle_packet( lv_packet ).
    ENDWHILE.
    rv_data = mv_outbound.
    CLEAR mv_outbound.
  ENDMETHOD.


  METHOD frame.
* Section 3: uint32 length excludes itself and includes byte type plus body.
    DATA lo_packet TYPE REF TO zcl_oassh_stream.
    lo_packet = NEW #( ).
    lo_packet->uint32_encode( xstrlen( iv_body ) + 1 ).
    lo_packet->byte_encode( iv_type ).
    lo_packet->append( iv_body ).
    rv_data = lo_packet->get( ).
  ENDMETHOD.


  METHOD build_request.
* Requests after INIT carry a client-selected id. Several may be outstanding;
* section 7 permits responses to arrive in a different order.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    DATA lv_id TYPE i.
    DATA lv_valid TYPE abap_bool.
    IF mv_state < c_state-ready OR mv_state >= c_state-finished.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    CASE iv_type.
      WHEN '03' OR '04' OR '05' OR '06' OR '07' OR '08' OR '09' OR '0A'
           OR '0B' OR '0C' OR '0D' OR '0E' OR '0F' OR '10' OR '11' OR '12'
           OR '13' OR '14' OR 'C8'.
        lv_valid = abap_true.
      WHEN OTHERS.
        lv_valid = abap_false.
    ENDCASE.
    IF lv_valid = abap_false.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    lv_id = next_request_id( ).
    lo_body = NEW #( ).
    lo_body->uint32_encode( lv_id ).
    lo_body->append( iv_body ).
    rv_data = frame(
      iv_type = iv_type
      iv_body = lo_body->get( ) ).
    INSERT lv_id INTO TABLE mt_request_ids.
  ENDMETHOD.


  METHOD next_request_id.
* int4 cannot represent request ids with the high bit set. Exhausting over two
* billion ids in one SFTP channel is outside the supported operation model.
    IF mv_next_request_id < 1.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    rv_id = mv_next_request_id.
    IF mv_next_request_id = 2147483647.
      mv_next_request_id = -1.
    ELSE.
      mv_next_request_id = mv_next_request_id + 1.
    ENDIF.
  ENDMETHOD.


  METHOD handle_packet.
    DATA lo_packet TYPE REF TO zcl_oassh_stream.
    DATA lv_type TYPE zcl_oassh_stream=>ty_byte.
    lo_packet = NEW #( iv_packet ).
    lv_type = lo_packet->byte_decode( ).
    IF mv_state = c_state-version_pending AND lv_type = '02'.
      handle_version( lo_packet ).
      RETURN.
    ENDIF.
    IF mv_state >= c_state-ready AND mv_state < c_state-finished.
      handle_response(
        iv_type   = lv_type
        io_packet = lo_packet ).
      RETURN.
    ENDIF.
    zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
  ENDMETHOD.


  METHOD handle_version.
* Section 4: VERSION has no request id. Require v3 and consume complete
* extension-name/data pairs before publishing the negotiated state.
    DATA lv_version TYPE i.
    DATA lv_extension_name TYPE xstring.
    DATA lv_extension_data TYPE xstring.
    lv_version = io_packet->uint32_decode( ).
    IF lv_version <> 3.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    WHILE io_packet->get_length( ) > 0.
      lv_extension_name = io_packet->string_decode( ).
      lv_extension_data = io_packet->string_decode( ).
    ENDWHILE.
    mv_version = lv_version.
    mv_state = c_state-ready.
    IF mv_operation = c_operation_download OR mv_operation = c_operation_upload.
      mv_outbound = open_request( ).
      mv_state = c_state-open_pending.
    ENDIF.
  ENDMETHOD.


  METHOD handle_response.
* Section 7 defines the v3 response set. Validate the echoed request id before
* exposing the response body to the operation state machine added in S2.
    DATA lv_id TYPE i.
    DATA lv_valid TYPE abap_bool.
    CASE iv_type.
      WHEN '65' OR '66' OR '67' OR '68' OR '69'.
        lv_valid = abap_true.
      WHEN OTHERS.
        lv_valid = abap_false.
    ENDCASE.
    IF lv_valid = abap_false.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    lv_id = io_packet->uint32_decode( ).
    READ TABLE mt_request_ids WITH TABLE KEY table_line = lv_id
      TRANSPORTING NO FIELDS.
    IF sy-subrc <> 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    IF ( mv_operation = c_operation_download OR mv_operation = c_operation_upload )
        AND mv_state <> c_state-ready.
      handle_download_response(
        iv_type   = iv_type
        io_packet = io_packet ).
    ELSE.
      mv_last_response_type = iv_type.
      mv_last_response_body = io_packet->get( ).
      mv_response_count = mv_response_count + 1.
    ENDIF.
    DELETE TABLE mt_request_ids WITH TABLE KEY table_line = lv_id.
  ENDMETHOD.


  METHOD handle_download_response.
* draft-ietf-secsh-filexfer-02 sections 6.3, 6.4 and 7. Parse a complete
* response before changing the operation state or publishing file bytes.
    DATA lv_handle TYPE xstring.
    DATA lv_data TYPE xstring.
    DATA lv_length TYPE i.
    DATA lv_max_offset TYPE i.
    DATA lv_status TYPE i.
    CASE mv_state.
      WHEN c_state-open_pending.
        CASE iv_type.
          WHEN '66'. " SSH_FXP_HANDLE
            lv_handle = io_packet->string_decode( ).
            ensure_consumed( io_packet ).
            IF lv_handle IS INITIAL OR xstrlen( lv_handle ) > 256.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            mv_handle = lv_handle.
            IF mv_operation = c_operation_download.
              mv_outbound = read_request( ).
              mv_state = c_state-read_pending.
            ELSEIF mv_upload_data IS INITIAL.
              mv_outbound = close_request( ).
              mv_state = c_state-close_pending.
            ELSE.
              mv_outbound = write_request( ).
              mv_state = c_state-write_pending.
            ENDIF.
          WHEN '65'. " SSH_FXP_STATUS: OPEN failed, so no handle exists
            lv_status = parse_status( io_packet ).
            IF lv_status = 0 OR lv_status = 1.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            mv_error_status = lv_status.
            mv_state = c_state-finished.
          WHEN OTHERS.
            zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDCASE.
      WHEN c_state-read_pending.
        CASE iv_type.
          WHEN '67'. " SSH_FXP_DATA
            lv_data = io_packet->string_decode( ).
            ensure_consumed( io_packet ).
            lv_length = xstrlen( lv_data ).
            lv_max_offset = 2147483647 - lv_length.
            IF lv_length > c_read_length OR mv_offset > lv_max_offset.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            IF lv_data IS NOT INITIAL.
              APPEND lv_data TO mt_data.
            ENDIF.
            mv_offset = mv_offset + lv_length.
            IF lv_length < c_read_length.
              mv_outbound = close_request( ).
              mv_state = c_state-close_pending.
            ELSE.
              mv_outbound = read_request( ).
            ENDIF.
          WHEN '65'. " EOF is normal; other status is retained through CLOSE
            lv_status = parse_status( io_packet ).
            IF lv_status <> 1.
              IF lv_status = 0.
                zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
              ENDIF.
              mv_error_status = lv_status.
            ENDIF.
            mv_outbound = close_request( ).
            mv_state = c_state-close_pending.
          WHEN OTHERS.
            zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDCASE.
      WHEN c_state-close_pending.
        IF iv_type <> '65'.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDIF.
        lv_status = parse_status( io_packet ).
        IF lv_status <> 0 AND mv_error_status < 0.
          mv_error_status = lv_status.
        ENDIF.
        mv_state = c_state-finished.
      WHEN c_state-write_pending.
        handle_write_response(
          iv_type   = iv_type
          io_packet = io_packet ).
      WHEN OTHERS.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDCASE.
  ENDMETHOD.


  METHOD handle_write_response.
    DATA lv_status TYPE i.
    DATA lv_upload_length TYPE i.
    IF iv_type <> '65'.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    lv_status = parse_status( io_packet ).
    IF lv_status = 0.
      mv_upload_position = mv_upload_position + mv_write_length.
      mv_offset = mv_offset + mv_write_length.
      lv_upload_length = xstrlen( mv_upload_data ).
      IF mv_upload_position < lv_upload_length.
        mv_outbound = write_request( ).
      ELSE.
        mv_outbound = close_request( ).
        mv_state = c_state-close_pending.
      ENDIF.
    ELSE.
      mv_error_status = lv_status.
      mv_outbound = close_request( ).
      mv_state = c_state-close_pending.
    ENDIF.
  ENDMETHOD.


  METHOD open_request.
* Section 6.3: OPEN(path, pflags, empty ATTRS flags).
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    DATA lv_pflags TYPE i.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_path ).
    IF mv_operation = c_operation_download.
      lv_pflags = 1. " SSH_FXF_READ
    ELSE.
      lv_pflags = 26. " SSH_FXF_WRITE | CREAT | TRUNC
    ENDIF.
    lo_body->uint32_encode( lv_pflags ).
    lo_body->uint32_encode( 0 ).
    rv_data = build_request(
      iv_type = '03'
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD read_request.
* Section 6.4: READ uses a uint64 offset and an interop-safe 32768-byte size.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_handle ).
    lo_body->uint64_encode( mv_offset ).
    lo_body->uint32_encode( c_read_length ).
    rv_data = build_request(
      iv_type = '05'
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD close_request.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_handle ).
    rv_data = build_request(
      iv_type = '04'
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD write_request.
* Section 6.4: WRITE carries a uint64 offset and an arbitrary binary string.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    DATA lv_remaining TYPE i.
    DATA lv_length TYPE i.
    DATA lv_chunk TYPE xstring.
    lv_remaining = xstrlen( mv_upload_data ) - mv_upload_position.
    lv_length = lv_remaining.
    IF lv_length > c_read_length.
      lv_length = c_read_length.
    ENDIF.
    lv_chunk = mv_upload_data+mv_upload_position(lv_length).
    lo_body = NEW #( ).
    lo_body->string_encode( mv_handle ).
    lo_body->uint64_encode( mv_offset ).
    lo_body->string_encode( lv_chunk ).
    rv_data = build_request(
      iv_type = '06'
      iv_body = lo_body->get( ) ).
    mv_write_length = lv_length.
  ENDMETHOD.


  METHOD parse_status.
* Section 7: STATUS always includes code, UTF-8 message, and language tag.
    rv_status = io_packet->uint32_decode( ).
    io_packet->string_decode( ).
    io_packet->string_decode( ).
    ensure_consumed( io_packet ).
    IF rv_status < 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
  ENDMETHOD.


  METHOD ensure_consumed.
    IF io_packet->get_length( ) <> 0.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
  ENDMETHOD.


  METHOD join_chunks.
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


  METHOD get_state.
    rv_state = mv_state.
  ENDMETHOD.


  METHOD get_version.
    rv_version = mv_version.
  ENDMETHOD.


  METHOD get_data.
    rv_data = join_chunks( mt_data ).
  ENDMETHOD.


  METHOD get_error_status.
    rv_status = mv_error_status.
  ENDMETHOD.
ENDCLASS.
