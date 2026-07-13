CLASS zcl_oassh_sftp DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    TYPES ty_uint32 TYPE x LENGTH 4.
    TYPES ty_uint64 TYPE x LENGTH 8.
    TYPES:
      BEGIN OF ty_extension,
        extension_type TYPE xstring,
        extension_data TYPE xstring,
      END OF ty_extension.
    TYPES ty_extensions TYPE STANDARD TABLE OF ty_extension WITH EMPTY KEY.
    TYPES:
      BEGIN OF ty_attrs,
        flags           TYPE ty_uint32,
        has_size        TYPE abap_bool,
        size            TYPE ty_uint64,
        has_uid_gid     TYPE abap_bool,
        uid             TYPE ty_uint32,
        gid             TYPE ty_uint32,
        has_permissions TYPE abap_bool,
        permissions     TYPE ty_uint32,
        has_acmodtime   TYPE abap_bool,
        atime           TYPE ty_uint32,
        mtime           TYPE ty_uint32,
        extensions      TYPE ty_extensions,
      END OF ty_attrs.
    TYPES:
      BEGIN OF ty_name,
        filename TYPE xstring,
        longname TYPE xstring,
        attrs    TYPE ty_attrs,
      END OF ty_name.
    TYPES ty_names TYPE STANDARD TABLE OF ty_name WITH EMPTY KEY.
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
        stat_pending    TYPE i VALUE 8,
        opendir_pending TYPE i VALUE 9,
        readdir_pending TYPE i VALUE 10,
        status_pending  TYPE i VALUE 11,
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
    METHODS start_stat
      IMPORTING
        iv_path        TYPE string
        iv_lstat       TYPE abap_bool DEFAULT abap_false
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS start_list
      IMPORTING
        iv_path        TYPE string
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS start_mkdir
      IMPORTING iv_path TYPE string
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS start_rmdir
      IMPORTING iv_path TYPE string
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS start_remove
      IMPORTING iv_path TYPE string
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS start_rename
      IMPORTING
        iv_old_path TYPE string
        iv_new_path TYPE string
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
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
    METHODS get_attrs
      RETURNING
        VALUE(rs_attrs) TYPE ty_attrs.
    METHODS get_names
      RETURNING
        VALUE(rt_names) TYPE ty_names.

  PRIVATE SECTION.
    TYPES ty_request_ids TYPE SORTED TABLE OF i WITH UNIQUE KEY table_line.
    TYPES ty_chunks TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    CONSTANTS c_operation_download TYPE i VALUE 1.
    CONSTANTS c_operation_upload TYPE i VALUE 2.
    CONSTANTS c_operation_stat TYPE i VALUE 3.
    CONSTANTS c_operation_lstat TYPE i VALUE 4.
    CONSTANTS c_operation_list TYPE i VALUE 5.
    CONSTANTS c_operation_mkdir TYPE i VALUE 6.
    CONSTANTS c_operation_rmdir TYPE i VALUE 7.
    CONSTANTS c_operation_remove TYPE i VALUE 8.
    CONSTANTS c_operation_rename TYPE i VALUE 9.
    CONSTANTS c_read_length TYPE i VALUE 32768.
    CONSTANTS c_max_directory_entries TYPE i VALUE 100000.

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
    DATA mv_path2 TYPE xstring.
    DATA mv_handle TYPE xstring.
    DATA mv_offset TYPE i.
    DATA mt_data TYPE ty_chunks.
    DATA mv_error_status TYPE i VALUE -1.
    DATA mv_outbound TYPE xstring.
    DATA mv_upload_data TYPE xstring.
    DATA mv_upload_position TYPE i.
    DATA mv_write_length TYPE i.
    DATA ms_attrs TYPE ty_attrs.
    DATA mt_names TYPE ty_names.

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
    METHODS stat_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS opendir_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS readdir_request
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS mutation_request
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS start_mutation
      IMPORTING
        iv_operation TYPE i
        iv_path      TYPE string
        iv_path2     TYPE string OPTIONAL
      RETURNING VALUE(rv_data) TYPE xstring
      RAISING zcx_oassh_error.
    METHODS handle_status_response
      IMPORTING
        iv_type   TYPE zcl_oassh_stream=>ty_byte
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING zcx_oassh_error.
    METHODS handle_list_response
      IMPORTING
        iv_type   TYPE zcl_oassh_stream=>ty_byte
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    METHODS handle_attrs_response
      IMPORTING
        iv_type   TYPE zcl_oassh_stream=>ty_byte
        io_packet TYPE REF TO zcl_oassh_stream
      RAISING
        zcx_oassh_error.
    CLASS-METHODS parse_attrs
      IMPORTING
        io_packet       TYPE REF TO zcl_oassh_stream
        iv_require_consumed TYPE abap_bool DEFAULT abap_true
      RETURNING
        VALUE(rs_attrs) TYPE ty_attrs
      RAISING
        zcx_oassh_error.
    CLASS-METHODS flag_is_set
      IMPORTING
        iv_flags      TYPE ty_uint32
        iv_bit        TYPE i
      RETURNING
        VALUE(rv_set) TYPE abap_bool.
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


  METHOD start_stat.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    IF iv_lstat = abap_true.
      mv_operation = c_operation_lstat.
    ELSE.
      mv_operation = c_operation_stat.
    ENDIF.
    mv_path = zcl_oassh_ascii=>to_xstring_text( iv_path ).
    rv_data = start( ).
  ENDMETHOD.


  METHOD start_list.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    mv_operation = c_operation_list.
    mv_path = zcl_oassh_ascii=>to_xstring_text( iv_path ).
    rv_data = start( ).
  ENDMETHOD.


  METHOD start_mkdir.
    rv_data = start_mutation(
      iv_operation = c_operation_mkdir
      iv_path      = iv_path ).
  ENDMETHOD.


  METHOD start_rmdir.
    rv_data = start_mutation(
      iv_operation = c_operation_rmdir
      iv_path      = iv_path ).
  ENDMETHOD.


  METHOD start_remove.
    rv_data = start_mutation(
      iv_operation = c_operation_remove
      iv_path      = iv_path ).
  ENDMETHOD.


  METHOD start_rename.
    rv_data = start_mutation(
      iv_operation = c_operation_rename
      iv_path      = iv_old_path
      iv_path2     = iv_new_path ).
  ENDMETHOD.


  METHOD start_mutation.
    IF mv_state <> c_state-created.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    mv_operation = iv_operation.
    mv_path = zcl_oassh_ascii=>to_xstring_text( iv_path ).
    mv_path2 = zcl_oassh_ascii=>to_xstring_text( iv_path2 ).
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
    IF mv_state < c_state-ready OR mv_state = c_state-finished.
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
    IF mv_state >= c_state-ready AND mv_state <> c_state-finished.
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
    CASE mv_operation.
      WHEN c_operation_download OR c_operation_upload.
        mv_outbound = open_request( ).
        mv_state = c_state-open_pending.
      WHEN c_operation_stat OR c_operation_lstat.
        mv_outbound = stat_request( ).
        mv_state = c_state-stat_pending.
      WHEN c_operation_list.
        mv_outbound = opendir_request( ).
        mv_state = c_state-opendir_pending.
      WHEN c_operation_mkdir OR c_operation_rmdir
          OR c_operation_remove OR c_operation_rename.
        mv_outbound = mutation_request( ).
        mv_state = c_state-status_pending.
    ENDCASE.
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
    ELSEIF ( mv_operation = c_operation_stat OR mv_operation = c_operation_lstat )
        AND mv_state = c_state-stat_pending.
      handle_attrs_response(
        iv_type   = iv_type
        io_packet = io_packet ).
    ELSEIF mv_operation = c_operation_list
        AND ( mv_state = c_state-opendir_pending
          OR mv_state = c_state-readdir_pending
          OR mv_state = c_state-close_pending ).
      handle_list_response(
        iv_type   = iv_type
        io_packet = io_packet ).
    ELSEIF ( mv_operation = c_operation_mkdir OR mv_operation = c_operation_rmdir
          OR mv_operation = c_operation_remove OR mv_operation = c_operation_rename )
        AND mv_state = c_state-status_pending.
      handle_status_response(
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


  METHOD stat_request.
* draft-ietf-secsh-filexfer-02 section 6.8: STAT follows links while LSTAT
* returns attributes for the link itself. Both requests contain only a path.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    DATA lv_type TYPE zcl_oassh_stream=>ty_byte.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_path ).
    IF mv_operation = c_operation_lstat.
      lv_type = '07'. " SSH_FXP_LSTAT
    ELSE.
      lv_type = '11'. " SSH_FXP_STAT
    ENDIF.
    rv_data = build_request(
      iv_type = lv_type
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD opendir_request.
* Section 6.7: OPENDIR contains the directory path and returns an opaque handle.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_path ).
    rv_data = build_request(
      iv_type = '0B'
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD readdir_request.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_handle ).
    rv_data = build_request(
      iv_type = '0C'
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD mutation_request.
* draft-ietf-secsh-filexfer-02 sections 6.5, 6.6, and 6.7 define these
* path-based v3 requests. MKDIR carries an empty ATTRS flags word.
    DATA lo_body TYPE REF TO zcl_oassh_stream.
    DATA lv_type TYPE zcl_oassh_stream=>ty_byte.
    lo_body = NEW #( ).
    lo_body->string_encode( mv_path ).
    CASE mv_operation.
      WHEN c_operation_remove.
        lv_type = '0D'.
      WHEN c_operation_mkdir.
        lv_type = '0E'.
        lo_body->uint32_encode( 0 ).
      WHEN c_operation_rmdir.
        lv_type = '0F'.
      WHEN c_operation_rename.
        lv_type = '12'.
        lo_body->string_encode( mv_path2 ).
      WHEN OTHERS.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDCASE.
    rv_data = build_request(
      iv_type = lv_type
      iv_body = lo_body->get( ) ).
  ENDMETHOD.


  METHOD handle_status_response.
    DATA lv_status TYPE i.
    IF iv_type <> '65'. " SSH_FXP_STATUS
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDIF.
    lv_status = parse_status( io_packet ).
    IF lv_status <> 0.
      mv_error_status = lv_status.
    ENDIF.
    mv_state = c_state-finished.
  ENDMETHOD.


  METHOD handle_list_response.
* Sections 6.7 and 7: consume every NAME batch, repeat READDIR until EOF, and
* close the directory handle on EOF or any READDIR status failure.
    DATA lv_handle TYPE xstring.
    DATA lv_status TYPE i.
    DATA lv_count TYPE i.
    DATA lv_total TYPE i.
    DATA ls_name TYPE ty_name.
    CASE mv_state.
      WHEN c_state-opendir_pending.
        CASE iv_type.
          WHEN '66'. " SSH_FXP_HANDLE
            lv_handle = io_packet->string_decode( ).
            ensure_consumed( io_packet ).
            IF lv_handle IS INITIAL OR xstrlen( lv_handle ) > 256.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            mv_handle = lv_handle.
            mv_outbound = readdir_request( ).
            mv_state = c_state-readdir_pending.
          WHEN '65'.
            lv_status = parse_status( io_packet ).
            IF lv_status = 0 OR lv_status = 1.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            mv_error_status = lv_status.
            mv_state = c_state-finished.
          WHEN OTHERS.
            zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDCASE.
      WHEN c_state-readdir_pending.
        CASE iv_type.
          WHEN '68'. " SSH_FXP_NAME
            lv_count = io_packet->uint32_decode( ).
            IF lv_count <= 0 OR lv_count > 4096.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            lv_total = lines( mt_names ) + lv_count.
            IF lv_total > c_max_directory_entries.
              zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
            ENDIF.
            DO lv_count TIMES.
              CLEAR ls_name.
              ls_name-filename = io_packet->string_decode( ).
              ls_name-longname = io_packet->string_decode( ).
              ls_name-attrs = parse_attrs(
                io_packet           = io_packet
                iv_require_consumed = abap_false ).
              APPEND ls_name TO mt_names.
            ENDDO.
            ensure_consumed( io_packet ).
            mv_outbound = readdir_request( ).
          WHEN '65'.
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
      WHEN OTHERS.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDCASE.
  ENDMETHOD.


  METHOD handle_attrs_response.
    DATA lv_status TYPE i.
    CASE iv_type.
      WHEN '69'. " SSH_FXP_ATTRS
        ms_attrs = parse_attrs( io_packet ).
      WHEN '65'. " SSH_FXP_STATUS
        lv_status = parse_status( io_packet ).
        IF lv_status = 0 OR lv_status = 1.
          zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
        ENDIF.
        mv_error_status = lv_status.
      WHEN OTHERS.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDCASE.
    mv_state = c_state-finished.
  ENDMETHOD.


  METHOD parse_attrs.
* Section 5 fixes both field order and flag semantics. Unsupported v3 bits
* are a protocol error; raw unsigned values remain byte-exact for portable ABAP.
    DATA lv_flags TYPE ty_uint32.
    DATA lv_bit_index TYPE i.
    DATA lv_bit TYPE c LENGTH 1.
    DATA lv_count TYPE i.
    DATA ls_extension TYPE ty_extension.
    lv_flags = io_packet->take( 4 ).
    lv_bit_index = 2.
    WHILE lv_bit_index <= 28.
      GET BIT lv_bit_index OF lv_flags INTO lv_bit.
      IF lv_bit = '1'.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
      ENDIF.
      lv_bit_index = lv_bit_index + 1.
    ENDWHILE.
    rs_attrs-flags = lv_flags.
    rs_attrs-has_size = flag_is_set(
      iv_flags = lv_flags
      iv_bit   = 32 ).
    rs_attrs-has_uid_gid = flag_is_set(
      iv_flags = lv_flags
      iv_bit   = 31 ).
    rs_attrs-has_permissions = flag_is_set(
      iv_flags = lv_flags
      iv_bit   = 30 ).
    rs_attrs-has_acmodtime = flag_is_set(
      iv_flags = lv_flags
      iv_bit   = 29 ).
    IF rs_attrs-has_size = abap_true.
      rs_attrs-size = io_packet->take( 8 ).
    ENDIF.
    IF rs_attrs-has_uid_gid = abap_true.
      rs_attrs-uid = io_packet->take( 4 ).
      rs_attrs-gid = io_packet->take( 4 ).
    ENDIF.
    IF rs_attrs-has_permissions = abap_true.
      rs_attrs-permissions = io_packet->take( 4 ).
    ENDIF.
    IF rs_attrs-has_acmodtime = abap_true.
      rs_attrs-atime = io_packet->take( 4 ).
      rs_attrs-mtime = io_packet->take( 4 ).
    ENDIF.
    IF flag_is_set(
        iv_flags = lv_flags
        iv_bit   = 1 ) = abap_true.
      lv_count = io_packet->uint32_decode( ).
      IF lv_count < 0 OR lv_count > 1024.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-sftp_protocol ).
      ENDIF.
      DO lv_count TIMES.
        CLEAR ls_extension.
        ls_extension-extension_type = io_packet->string_decode( ).
        ls_extension-extension_data = io_packet->string_decode( ).
        APPEND ls_extension TO rs_attrs-extensions.
      ENDDO.
    ENDIF.
    IF iv_require_consumed = abap_true.
      ensure_consumed( io_packet ).
    ENDIF.
  ENDMETHOD.


  METHOD flag_is_set.
    DATA lv_bit TYPE c LENGTH 1.
    GET BIT iv_bit OF iv_flags INTO lv_bit.
    rv_set = xsdbool( lv_bit = '1' ).
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


  METHOD get_attrs.
    rs_attrs = ms_attrs.
  ENDMETHOD.


  METHOD get_names.
    rt_names = mt_names.
  ENDMETHOD.
ENDCLASS.
