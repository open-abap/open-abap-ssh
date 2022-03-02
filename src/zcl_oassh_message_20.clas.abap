CLASS zcl_oassh_message_20 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.

    TYPES:
      BEGIN OF ty_data,
        message_id                    TYPE x LENGTH 1,
        cookie                        TYPE x LENGTH 16,
        kex_algorithms                TYPE string_table,
        server_host_key_algorithms    TYPE string_table,
        encryption_algorithms_c_to_s  TYPE string_table,
        encryption_algorithms_s_to_c  TYPE string_table,
        mac_algorithms_c_to_s         TYPE string_table,
        mac_algorithms_s_to_c         TYPE string_table,
        compression_algorithms_c_to_s TYPE string_table,
        compression_algorithms_s_to_c TYPE string_table,
        languages_c_to_s              TYPE string_table,
        languages_s_to_c              TYPE string_table,
        first_kex_packet_follows      TYPE abap_bool,
        reserved                      TYPE i,
      END OF ty_data .

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

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '14'. " is 20 in decimal

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_message_20 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
* SSH_MSG_KEXINIT

    rs_data-message_id = io_stream->take( 1 ).
    ASSERT rs_data-message_id = gc_message_id.
    rs_data-cookie = io_stream->take( 16 ).
    rs_data-kex_algorithms = io_stream->name_list_decode( ).
    rs_data-server_host_key_algorithms = io_stream->name_list_decode( ).
    rs_data-encryption_algorithms_c_to_s = io_stream->name_list_decode( ).
    rs_data-encryption_algorithms_s_to_c = io_stream->name_list_decode( ).
    rs_data-mac_algorithms_c_to_s = io_stream->name_list_decode( ).
    rs_data-mac_algorithms_s_to_c = io_stream->name_list_decode( ).
    rs_data-compression_algorithms_c_to_s = io_stream->name_list_decode( ).
    rs_data-compression_algorithms_s_to_c = io_stream->name_list_decode( ).
    rs_data-languages_c_to_s = io_stream->name_list_decode( ).
    rs_data-languages_s_to_c = io_stream->name_list_decode( ).
    rs_data-first_kex_packet_follows = io_stream->boolean_decode( ).
    rs_data-reserved = io_stream->uint32_decode( ).

  ENDMETHOD.


  METHOD serialize.

    CREATE OBJECT ro_stream.
    ro_stream->append( gc_message_id ).
    ro_stream->append( is_data-cookie ).
    ro_stream->name_list_encode( is_data-kex_algorithms ).
    ro_stream->name_list_encode( is_data-server_host_key_algorithms ).
    ro_stream->name_list_encode( is_data-encryption_algorithms_c_to_s ).
    ro_stream->name_list_encode( is_data-encryption_algorithms_s_to_c ).
    ro_stream->name_list_encode( is_data-mac_algorithms_c_to_s ).
    ro_stream->name_list_encode( is_data-mac_algorithms_s_to_c ).
    ro_stream->name_list_encode( is_data-compression_algorithms_c_to_s ).
    ro_stream->name_list_encode( is_data-compression_algorithms_s_to_c ).
    ro_stream->name_list_encode( is_data-languages_c_to_s ).
    ro_stream->name_list_encode( is_data-languages_s_to_c ).
    ro_stream->boolean_encode( is_data-first_kex_packet_follows ).
    ro_stream->uint32_encode( is_data-reserved ).

  ENDMETHOD.
ENDCLASS.