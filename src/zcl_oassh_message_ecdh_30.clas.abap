CLASS zcl_oassh_message_ecdh_30 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id TYPE x LENGTH 1,
        q_c        TYPE xstring,
      END OF ty_data .

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '1E'. " is 30 in decimal

    CLASS-METHODS parse
      IMPORTING
        !io_stream     TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rs_data) TYPE ty_data .

    CLASS-METHODS serialize
      IMPORTING
        is_data          TYPE ty_data
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream .

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS ZCL_OASSH_MESSAGE_ECDH_30 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc5656#section-7.1
* https://datatracker.ietf.org/doc/html/rfc5656#section-4

    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-q_c = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    CREATE OBJECT ro_stream.
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-q_c ).

  ENDMETHOD.
ENDCLASS.
