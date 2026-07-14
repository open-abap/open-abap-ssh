CLASS zcl_oassh_message_6 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id   TYPE x LENGTH 1,
        service_name TYPE xstring,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '06'. " is 6 in decimal

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



CLASS zcl_oassh_message_6 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4253#section-10
* SSH_MSG_SERVICE_ACCEPT

    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    rs_data-service_name = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-service_name ).

  ENDMETHOD.
ENDCLASS.
