CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE.

  PUBLIC SECTION.

    INTERFACES zif_oassh_socket_handler.

    CLASS-METHODS connect
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string
      RAISING
        cx_static_check.

    METHODS constructor
      IMPORTING
        ii_socket TYPE REF TO zif_oassh_socket.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      BEGIN OF gc_state,
        protocol_version_exchange TYPE i VALUE 1,
        key_exchange              TYPE i VALUE 2,
      END OF gc_state.
    DATA mi_socket TYPE REF TO zif_oassh_socket.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    DATA mv_state  TYPE i.

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
        ii_socket = li_socket.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

  ENDMETHOD.


  METHOD constructor.
    mi_socket = ii_socket.
    CREATE OBJECT mo_stream.
  ENDMETHOD.


  METHOD handle.

    DATA lv_padding_length TYPE i.
    DATA lv_length         TYPE i.
    DATA ls_kexinit        TYPE zcl_oassh_message_20=>ty_data.

    CASE mv_state.
      WHEN gc_state-protocol_version_exchange.
        IF mo_stream->get( ) CP |*{ zcl_oassh_ascii=>c_cr_lf }|.
          mo_stream->clear( ).
          mv_state = gc_state-key_exchange.
        ENDIF.
      WHEN gc_state-key_exchange.
* https://datatracker.ietf.org/doc/html/rfc4253#section-7

        IF mo_stream->get_length( ) > 4.
          lv_length = mo_stream->uint32_decode_peek( ).
          IF mo_stream->get_length( ) = lv_length.
            mo_stream->uint32_decode( ).
* there is no MAC negotiated at this point in time
            lv_padding_length = mo_stream->take( 1 ).
            ls_kexinit = zcl_oassh_message_20=>parse( mo_stream ).
            mo_stream->take( lv_padding_length / 2 ).

            ls_kexinit-cookie = '11223344556677881122334455667788'. " todo, this should value should be random
            mi_socket->send( zcl_oassh_message_20=>serialize( ls_kexinit )->get( ) ).
          ENDIF.
        ENDIF.

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
    lv_xstr = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ) && zcl_oassh_ascii=>c_cr_lf.

    mi_socket->send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.
ENDCLASS.
