CLASS zcl_oassh_message_dh_31 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_data,
        message_id TYPE x LENGTH 1,
        k_s        TYPE xstring,
        f          TYPE xstring,
        signature  TYPE xstring,
      END OF ty_data.
    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '1F'.
    CLASS-METHODS parse
      IMPORTING io_stream TYPE REF TO zcl_oassh_stream
      RETURNING VALUE(rs_data) TYPE ty_data
      RAISING zcx_oassh_error.
    CLASS-METHODS serialize
      IMPORTING is_data TYPE ty_data
      RETURNING VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
ENDCLASS.


CLASS zcl_oassh_message_dh_31 IMPLEMENTATION.
  METHOD parse.
* RFC 4253 section 8: K_S and signature are strings; f is an mpint.
    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    rs_data-k_s = io_stream->string_decode( ).
    rs_data-f = io_stream->mpint_decode_positive( ).
    rs_data-signature = io_stream->string_decode( ).
  ENDMETHOD.


  METHOD serialize.
    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-k_s ).
    ro_stream->mpint_encode( is_data-f ).
    ro_stream->string_encode( is_data-signature ).
  ENDMETHOD.
ENDCLASS.
