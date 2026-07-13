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
      END OF c_state.

    METHODS constructor.
    METHODS start
      RETURNING
        VALUE(rv_data) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS receive
      IMPORTING
        iv_data TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS get_state
      RETURNING
        VALUE(rv_state) TYPE i.
    METHODS get_version
      RETURNING
        VALUE(rv_version) TYPE i.

  PRIVATE SECTION.
    TYPES ty_request_ids TYPE SORTED TABLE OF i WITH UNIQUE KEY table_line.

    DATA mo_receive TYPE REF TO zcl_oassh_stream.
    DATA mv_expected_length TYPE i.
    DATA mv_state TYPE i.
    DATA mv_version TYPE i.
    DATA mv_next_request_id TYPE i VALUE 1.
    DATA mt_request_ids TYPE ty_request_ids.
    DATA mv_response_count TYPE i.
    DATA mv_last_response_type TYPE zcl_oassh_stream=>ty_byte.
    DATA mv_last_response_body TYPE xstring.

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
    IF mv_state <> c_state-ready.
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
    IF mv_state = c_state-ready.
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
    DELETE TABLE mt_request_ids WITH TABLE KEY table_line = lv_id.
    mv_last_response_type = iv_type.
    mv_last_response_body = io_packet->get( ).
    mv_response_count = mv_response_count + 1.
  ENDMETHOD.


  METHOD get_state.
    rv_state = mv_state.
  ENDMETHOD.


  METHOD get_version.
    rv_version = mv_version.
  ENDMETHOD.
ENDCLASS.
