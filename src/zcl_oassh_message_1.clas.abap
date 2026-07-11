CLASS zcl_oassh_message_1 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id   TYPE x LENGTH 1,
        reason_code  TYPE i,
        description  TYPE xstring,
        language_tag TYPE xstring,
      END OF ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '01'. " is 1 in decimal

* https://datatracker.ietf.org/doc/html/rfc4253#section-11.1
    CONSTANTS:
      BEGIN OF c_reason,
        host_not_allowed_to_connect     TYPE i VALUE 1,
        protocol_error                  TYPE i VALUE 2,
        key_exchange_failed             TYPE i VALUE 3,
        reserved                        TYPE i VALUE 4,
        mac_error                       TYPE i VALUE 5,
        compression_error               TYPE i VALUE 6,
        service_not_available           TYPE i VALUE 7,
        protocol_version_not_supported  TYPE i VALUE 8,
        host_key_not_verifiable         TYPE i VALUE 9,
        connection_lost                 TYPE i VALUE 10,
        by_application                  TYPE i VALUE 11,
        too_many_connections            TYPE i VALUE 12,
        auth_cancelled_by_user          TYPE i VALUE 13,
        no_more_auth_methods_available  TYPE i VALUE 14,
        illegal_user_name               TYPE i VALUE 15,
      END OF c_reason.

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



CLASS zcl_oassh_message_1 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4253#section-11.1
* SSH_MSG_DISCONNECT

    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-reason_code = io_stream->uint32_decode( ).
    rs_data-description = io_stream->string_decode( ).
    rs_data-language_tag = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->uint32_encode( is_data-reason_code ).
    ro_stream->string_encode( is_data-description ).
    ro_stream->string_encode( is_data-language_tag ).

  ENDMETHOD.
ENDCLASS.
