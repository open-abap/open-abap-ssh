CLASS zcl_oassh_message_51 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id      TYPE x LENGTH 1,
        authentications TYPE string_table,
        partial_success TYPE abap_bool,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '33'. " is 51 in decimal

    CLASS-METHODS parse
      IMPORTING
        io_stream      TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rs_data) TYPE ty_data
      RAISING zcx_oassh_error.

    CLASS-METHODS serialize
      IMPORTING
        is_data          TYPE ty_data
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_message_51 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
* SSH_MSG_USERAUTH_FAILURE

    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    rs_data-authentications = io_stream->name_list_decode( ).
    rs_data-partial_success = io_stream->boolean_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->name_list_encode( is_data-authentications ).
    ro_stream->boolean_encode( is_data-partial_success ).

  ENDMETHOD.
ENDCLASS.
