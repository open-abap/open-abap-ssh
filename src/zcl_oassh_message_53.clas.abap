CLASS zcl_oassh_message_53 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id   TYPE x LENGTH 1,
        message      TYPE xstring,
        language_tag TYPE xstring,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '35'. " is 53 in decimal

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



CLASS zcl_oassh_message_53 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4252#section-5.4
* SSH_MSG_USERAUTH_BANNER

    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-message = io_stream->string_decode( ).
    rs_data-language_tag = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-message ).
    ro_stream->string_encode( is_data-language_tag ).

  ENDMETHOD.
ENDCLASS.
