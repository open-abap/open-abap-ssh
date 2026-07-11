CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE.

  PUBLIC SECTION.

    INTERFACES zif_oassh_socket_handler.

    CLASS-METHODS connect
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string
        iv_user TYPE string
        iv_password TYPE string
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
      RAISING
        cx_static_check.

    METHODS constructor
      IMPORTING
        ii_socket TYPE REF TO zif_oassh_socket
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
        iv_user TYPE string
        iv_password TYPE string.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      BEGIN OF gc_state,
        protocol_version_exchange TYPE i VALUE 1,
        key_exchange              TYPE i VALUE 2,
        encrypted                 TYPE i VALUE 3,
      END OF gc_state.
    DATA mi_socket TYPE REF TO zif_oassh_socket.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    DATA mo_plain_packet TYPE REF TO zcl_oassh_packet.
    DATA mo_transport TYPE REF TO zcl_oassh_transport.
    DATA mv_state  TYPE i.
    DATA mv_client_version TYPE xstring.
    DATA mv_user TYPE xstring.
    DATA mv_password TYPE xstring.
    DATA mv_enc_packet_length TYPE i.

    METHODS handle
      RAISING
        cx_static_check.
    METHODS process_version
      RAISING
        cx_static_check.
    METHODS process_kex
      RAISING
        cx_static_check.
    METHODS process_encrypted
      RAISING
        cx_static_check.
ENDCLASS.



CLASS zcl_oassh IMPLEMENTATION.


  METHOD connect.

    DATA lo_ssh    TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.

    li_socket = NEW zcl_oassh_socket_apc(
      iv_host = iv_host
      iv_port = iv_port ).

    CREATE OBJECT lo_ssh
      EXPORTING
        ii_socket        = li_socket
        ii_random        = ii_random
        ii_host_verifier = ii_host_verifier
        iv_user          = iv_user
        iv_password      = iv_password.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

  ENDMETHOD.


  METHOD constructor.
    mi_socket = ii_socket.
    mi_random = ii_random.
    mv_user = zcl_oassh_ascii=>to_xstring( iv_user ).
    mv_password = zcl_oassh_ascii=>to_xstring( iv_password ).
    CREATE OBJECT mo_stream.
    mo_plain_packet = NEW #( ii_random = mi_random ).
    mo_transport = NEW #(
      ii_random        = mi_random
      ii_host_verifier = ii_host_verifier ).
  ENDMETHOD.


  METHOD handle.
* Each phase runs in its own method: the transpiler mis-scopes the sy-index
* backup variable for a RETURN inside a loop that is nested in a CASE branch,
* so keeping one loop per method avoids the generated ReferenceError.
* State transitions fall through within a single call: version -> kex -> auth.
    IF mv_state = gc_state-protocol_version_exchange.
      process_version( ).
    ENDIF.
    IF mv_state = gc_state-key_exchange.
      process_kex( ).
    ENDIF.
    IF mv_state = gc_state-encrypted.
      process_encrypted( ).
    ENDIF.
  ENDMETHOD.


  METHOD process_version.
* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
    DATA lv_version_data TYPE xstring.
    DATA lv_version_length TYPE i.
    DATA lv_offset TYPE i.
    DATA lv_server_version TYPE xstring.
    DATA lv_payload TYPE xstring.
    lv_version_data = mo_stream->get( ).
    lv_version_length = xstrlen( lv_version_data ).
    WHILE lv_offset + 1 < lv_version_length.
      IF lv_version_data+lv_offset(2) = zcl_oassh_ascii=>c_cr_lf.
        lv_server_version = mo_stream->take( lv_offset ).
        mo_stream->take( 2 ).
        ASSERT lv_server_version(4) = '5353482D'.
        lv_payload = mo_transport->start_kex(
          iv_client_version = mv_client_version
          iv_server_version = lv_server_version ).
        mi_socket->send( mo_plain_packet->encode( lv_payload ) ).
        mv_state = gc_state-key_exchange.
        RETURN.
      ENDIF.
      lv_offset = lv_offset + 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD process_kex.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7
    DATA lv_length TYPE i.
    DATA lv_total_length TYPE i.
    DATA lv_wire TYPE xstring.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    WHILE mo_stream->get_length( ) >= 8.
      lv_length = mo_stream->uint32_decode_peek( ).
      lv_total_length = lv_length + 4.
      IF mo_stream->get_length( ) < lv_total_length.
        RETURN.
      ENDIF.
      lv_wire = mo_stream->take( lv_total_length ).
      lv_payload = mo_plain_packet->decode( lv_wire ).
      CASE mo_transport->get_state( ).
        WHEN zcl_oassh_transport=>c_state-kexinit_sent.
          lv_reply = mo_transport->receive_kexinit( lv_payload ).
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
        WHEN zcl_oassh_transport=>c_state-ecdh_sent.
          lv_reply = mo_transport->receive_ecdh_reply( lv_payload ).
          mi_socket->send( mo_plain_packet->encode( lv_reply ) ).
        WHEN zcl_oassh_transport=>c_state-newkeys_sent.
          mo_transport->receive_newkeys( lv_payload ).
          mv_state = gc_state-encrypted.
          lv_reply = mo_transport->start_auth(
            iv_user     = mv_user
            iv_password = mv_password ).
          mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
          RETURN.
        WHEN OTHERS.
          ASSERT 1 = 2.
      ENDCASE.
    ENDWHILE.
  ENDMETHOD.


  METHOD process_encrypted.
* https://datatracker.ietf.org/doc/html/rfc4253#section-6
* the packet_length field is encrypted, so decrypt the first block to frame
    DATA lv_block TYPE xstring.
    DATA lv_rest TYPE xstring.
    DATA lv_mac TYPE xstring.
    DATA lv_remaining TYPE i.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    WHILE mo_stream->get_length( ) > 0.
      IF mv_enc_packet_length = 0.
        IF mo_stream->get_length( ) < 16.
          RETURN.
        ENDIF.
        lv_block = mo_stream->take( 16 ).
        mv_enc_packet_length = mo_transport->get_packet( )->decode_length( lv_block ).
      ENDIF.
      lv_remaining = mv_enc_packet_length + 4 - 16 + 32.
      IF mo_stream->get_length( ) < lv_remaining.
        RETURN.
      ENDIF.
      lv_rest = mo_stream->take( mv_enc_packet_length + 4 - 16 ).
      lv_mac = mo_stream->take( 32 ).
      lv_payload = mo_transport->get_packet( )->decode_remainder(
        iv_rest = lv_rest
        iv_mac  = lv_mac ).
      mv_enc_packet_length = 0.
      lv_reply = mo_transport->receive_auth( lv_payload ).
      IF lv_reply IS NOT INITIAL.
        mi_socket->send( mo_transport->get_packet( )->encode( lv_reply ) ).
      ENDIF.
    ENDWHILE.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_close.
    RETURN.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_error.
    RETURN.
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_message.
    mo_stream->append( iv_data ).
    handle( ).
  ENDMETHOD.


  METHOD zif_oassh_socket_handler~on_open.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    DATA lv_xstr TYPE xstring.
    mv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ).
    lv_xstr = mv_client_version && zcl_oassh_ascii=>c_cr_lf.

    mi_socket->send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.
ENDCLASS.
