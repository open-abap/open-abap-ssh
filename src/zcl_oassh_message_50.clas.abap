CLASS zcl_oassh_message_50 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* SSH_MSG_USERAUTH_REQUEST for the "password" method only (RFC 4252 section 8).
* The "publickey" and other methods are out of scope for v1.
    TYPES:
      BEGIN OF ty_data,
        message_id   TYPE x LENGTH 1,
        user_name    TYPE xstring,
        service_name TYPE xstring,
        method_name  TYPE xstring,
        password     TYPE xstring,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '32'. " is 50 in decimal

    CLASS-METHODS parse
      IMPORTING
        io_stream      TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rs_data) TYPE ty_data.

    CLASS-METHODS serialize
      IMPORTING
        is_data          TYPE ty_data
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_message_50 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4252#section-8
* SSH_MSG_USERAUTH_REQUEST, password method

    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-user_name = io_stream->string_decode( ).
    rs_data-service_name = io_stream->string_decode( ).
    rs_data-method_name = io_stream->string_decode( ).
    ASSERT zcl_oassh_ascii=>from_xstring( rs_data-method_name ) = 'password'.
* the boolean FALSE means "this is not a password change request"
    ASSERT io_stream->boolean_decode( ) = abap_false.
    rs_data-password = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-user_name ).
    ro_stream->string_encode( is_data-service_name ).
    ro_stream->string_encode( is_data-method_name ).
    ro_stream->boolean_encode( abap_false ).
    ro_stream->string_encode( is_data-password ).

  ENDMETHOD.
ENDCLASS.
