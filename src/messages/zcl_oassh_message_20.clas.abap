CLASS zcl_oassh_message_20 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

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
      END OF ty_data.

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

    CLASS-METHODS create
      IMPORTING
        ii_random      TYPE REF TO zif_oassh_random
      RETURNING
        VALUE(rs_data) TYPE ty_data.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '14'. " is 20 in decimal

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_message_20 IMPLEMENTATION.


  METHOD create.
    rs_data-message_id = gc_message_id.
    rs_data-cookie = ii_random->bytes( 16 ).
    APPEND 'curve25519-sha256' TO rs_data-kex_algorithms.
    APPEND 'diffie-hellman-group14-sha256' TO rs_data-kex_algorithms.
    APPEND 'rsa-sha2-256' TO rs_data-server_host_key_algorithms.
    APPEND 'ssh-ed25519' TO rs_data-server_host_key_algorithms.
    APPEND 'aes128-ctr' TO rs_data-encryption_algorithms_c_to_s.
    APPEND 'chacha20-poly1305@openssh.com' TO rs_data-encryption_algorithms_c_to_s.
    APPEND 'aes128-ctr' TO rs_data-encryption_algorithms_s_to_c.
    APPEND 'chacha20-poly1305@openssh.com' TO rs_data-encryption_algorithms_s_to_c.
    APPEND 'hmac-sha2-256' TO rs_data-mac_algorithms_c_to_s.
    APPEND 'hmac-sha2-256' TO rs_data-mac_algorithms_s_to_c.
    APPEND 'none' TO rs_data-compression_algorithms_c_to_s.
    APPEND 'none' TO rs_data-compression_algorithms_s_to_c.
    rs_data-first_kex_packet_follows = abap_false.
  ENDMETHOD.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
* SSH_MSG_KEXINIT

    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
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
    IF rs_data-reserved <> 0.
* RFC 4253 section 7.1 requires the future-extension field to be zero.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
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
