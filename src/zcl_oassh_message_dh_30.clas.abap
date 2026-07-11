CLASS zcl_oassh_message_dh_30 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_data,
        message_id TYPE x LENGTH 1,
        e          TYPE xstring,
      END OF ty_data.
    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '1E'.
    CLASS-METHODS parse
      IMPORTING io_stream TYPE REF TO zcl_oassh_stream
      RETURNING VALUE(rs_data) TYPE ty_data
      RAISING zcx_oassh_error.
    CLASS-METHODS serialize
      IMPORTING is_data TYPE ty_data
      RETURNING VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
ENDCLASS.


CLASS zcl_oassh_message_dh_30 IMPLEMENTATION.
  METHOD parse.
* RFC 4253 section 8: SSH_MSG_KEXDH_INIT carries e as an mpint.
    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-e = io_stream->mpint_decode_positive( ).
  ENDMETHOD.


  METHOD serialize.
    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->mpint_encode( is_data-e ).
  ENDMETHOD.
ENDCLASS.
