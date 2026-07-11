CLASS zcl_oassh_socket_apc DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* zif_oassh_socket implementation on top of ABAP Push Channels (APC). This
* is the only place in the library that references the SAP standard APC
* classes; the SSH core talks to zif_oassh_socket / zif_oassh_socket_handler.

    INTERFACES zif_oassh_socket.
    INTERFACES if_apc_wsp_event_handler.

    METHODS constructor
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mv_host    TYPE string.
    DATA mv_port    TYPE string.
    DATA mi_client  TYPE REF TO if_apc_wsp_client.
    DATA mi_handler TYPE REF TO zif_oassh_socket_handler.
ENDCLASS.



CLASS zcl_oassh_socket_apc IMPLEMENTATION.


  METHOD constructor.
    mv_host = iv_host.
    mv_port = iv_port.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_close.
    IF mi_handler IS BOUND.
      mi_handler->on_close( ).
    ENDIF.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_error.
    IF mi_handler IS BOUND.
      mi_handler->on_error( ).
    ENDIF.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_message.

    DATA lx_error TYPE REF TO cx_root.

    IF mi_handler IS NOT BOUND.
      RETURN.
    ENDIF.

    TRY.
        mi_handler->on_message( i_message->get_binary( ) ).
      CATCH cx_root INTO lx_error.
        mi_handler->on_error( ).
    ENDTRY.

  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.

    DATA lx_error TYPE REF TO cx_root.

    IF mi_handler IS NOT BOUND.
      RETURN.
    ENDIF.

    TRY.
        mi_handler->on_open( ).
      CATCH cx_root INTO lx_error.
        mi_handler->on_error( ).
    ENDTRY.

  ENDMETHOD.


  METHOD zif_oassh_socket~connect.

    DATA ls_frame TYPE apc_tcp_frame.

* SSH has no fixed record length, so read one byte at a time and let the
* SSH core reassemble the version line and binary packets
    ls_frame-frame_type   = if_apc_tcp_frame_types=>co_frame_type_fixed_length.
    ls_frame-fixed_length = 1.

    mi_client = cl_apc_tcp_client_manager=>create(
      i_host          = mv_host
      i_port          = mv_port
      i_frame         = ls_frame
      i_event_handler = me ).

    mi_client->connect( ).

  ENDMETHOD.


  METHOD zif_oassh_socket~send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.
    DATA lv_index           TYPE i.
    DATA lv_hex             TYPE xstring.

    ASSERT iv_data IS NOT INITIAL.

    li_message_manager ?= mi_client->get_message_manager( ).
    li_message = li_message_manager->create_message( ).

    DO xstrlen( iv_data ) TIMES.
      lv_index = sy-index - 1.
      lv_hex = iv_data+lv_index(1).
      li_message->set_binary( lv_hex ).
      li_message_manager->send( li_message ).
    ENDDO.

  ENDMETHOD.


  METHOD zif_oassh_socket~set_handler.
    mi_handler = ii_handler.
  ENDMETHOD.
ENDCLASS.
