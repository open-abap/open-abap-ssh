CLASS zcl_oassh_message_52 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '34'. " is 52 in decimal
    CLASS-METHODS parse
      IMPORTING
        io_stream TYPE REF TO zcl_oassh_stream.
    CLASS-METHODS serialize
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
ENDCLASS.


CLASS zcl_oassh_message_52 IMPLEMENTATION.

  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
* SSH_MSG_USERAUTH_SUCCESS
    DATA lv_message_id TYPE x LENGTH 1.
    lv_message_id = io_stream->take( 1 ).
    ASSERT lv_message_id = gc_message_id.
  ENDMETHOD.


  METHOD serialize.
    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
  ENDMETHOD.
ENDCLASS.
