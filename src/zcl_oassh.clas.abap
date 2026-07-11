CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE.

  PUBLIC SECTION.

    INTERFACES zif_oassh_socket_handler.

    CLASS-METHODS connect
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
      RAISING
        cx_static_check.

    METHODS constructor
      IMPORTING
        ii_socket TYPE REF TO zif_oassh_socket
        ii_random TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier.
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

    METHODS handle
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
        ii_host_verifier = ii_host_verifier.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

  ENDMETHOD.


  METHOD constructor.
    mi_socket = ii_socket.
    mi_random = ii_random.
    CREATE OBJECT mo_stream.
    mo_plain_packet = NEW #( ii_random = mi_random ).
    mo_transport = NEW #(
      ii_random        = mi_random
      ii_host_verifier = ii_host_verifier ).
  ENDMETHOD.


  METHOD handle.

    DATA lv_length TYPE i.
    DATA lv_total_length TYPE i.
    DATA lv_wire TYPE xstring.
    DATA lv_payload TYPE xstring.
    DATA lv_reply TYPE xstring.
    DATA lv_server_version TYPE xstring.
    DATA lv_version_length TYPE i.
    DATA lv_version_data TYPE xstring.
    DATA lv_offset TYPE i.

    CASE mv_state.
      WHEN gc_state-protocol_version_exchange.
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
            IF mo_stream->get_length( ) > 0.
              handle( ).
            ENDIF.
            RETURN.
          ENDIF.
          lv_offset = lv_offset + 1.
        ENDWHILE.
      WHEN gc_state-key_exchange.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7
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
            WHEN OTHERS.
              ASSERT 1 = 2.
          ENDCASE.
        ENDWHILE.

    ENDCASE.

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
