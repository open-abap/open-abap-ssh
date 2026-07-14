CLASS zcl_oassh_message_4 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id     TYPE x LENGTH 1,
        always_display TYPE abap_bool,
        message        TYPE xstring,
        language_tag   TYPE xstring,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '04'. " is 4 in decimal

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



CLASS zcl_oassh_message_4 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4253#section-11.3
* SSH_MSG_DEBUG: informational; display only if always_display is set

    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    rs_data-always_display = io_stream->boolean_decode( ).
    rs_data-message = io_stream->string_decode( ).
    rs_data-language_tag = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->boolean_encode( is_data-always_display ).
    ro_stream->string_encode( is_data-message ).
    ro_stream->string_encode( is_data-language_tag ).

  ENDMETHOD.
ENDCLASS.
