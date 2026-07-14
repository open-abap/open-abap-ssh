CLASS zcl_oassh_message_21 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '15'.
    CLASS-METHODS parse
      IMPORTING
        io_stream TYPE REF TO zcl_oassh_stream
      RAISING zcx_oassh_error.
    CLASS-METHODS serialize
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
ENDCLASS.


CLASS zcl_oassh_message_21 IMPLEMENTATION.

  METHOD parse.
    DATA lv_message_id TYPE x LENGTH 1.
    lv_message_id = io_stream->take( 1 ).
    IF lv_message_id <> gc_message_id.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
  ENDMETHOD.


  METHOD serialize.
    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
  ENDMETHOD.
ENDCLASS.
