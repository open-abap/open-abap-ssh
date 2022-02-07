CLASS zcl_abapgit_ssh DEFINITION PUBLIC CREATE PRIVATE.
  PUBLIC SECTION.
    INTERFACES if_apc_wsp_event_handler.
    CLASS-METHODS connect
      IMPORTING
        iv_host TYPE string
        iv_port TYPE string
      RAISING
        cx_static_check.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mi_client TYPE REF TO if_apc_wsp_client .
    DATA mv_buffer TYPE xstring .

    METHODS send
      IMPORTING
        !iv_message TYPE xstring
      RAISING
        cx_apc_error .
ENDCLASS.



CLASS ZCL_ABAPGIT_SSH IMPLEMENTATION.


  METHOD connect.

    DATA(lo_ssh) = NEW zcl_abapgit_ssh( ).

    DATA(ls_frame) = VALUE apc_tcp_frame(
      frame_type   = if_apc_tcp_frame_types=>co_frame_type_fixed_length
      fixed_length = 1 ).

    lo_ssh->mi_client = cl_apc_tcp_client_manager=>create(
      i_host          = iv_host
      i_port          = iv_port
      i_frame         = ls_frame
      i_event_handler = lo_ssh ).

    lo_ssh->mi_client->connect( ).

  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_close.
    BREAK-POINT.
    WRITE / 'on_close'.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_error.
    BREAK-POINT.
    WRITE / 'on_error'.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_message.
    TRY.
        DATA(lv_message) = i_message->get_binary( ).
      CATCH cx_root.
    ENDTRY.
    mv_buffer = mv_buffer && lv_message.
    IF xstrlen( mv_buffer ) >= 24.
      BREAK-POINT.
    ENDIF.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.
    WRITE / 'on_open'.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
    DATA(lv_xstr) = cl_abap_codepage=>convert_to( 'SSH-2.0-abap' && cl_abap_char_utilities=>cr_lf ).

    send( lv_xstr ).

  ENDMETHOD.


  METHOD send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.
    DATA lv_index TYPE i.
    DATA lv_hex TYPE xstring.

    li_message_manager ?= mi_client->get_message_manager( ).

    li_message = li_message_manager->create_message( ).

    ASSERT NOT iv_message IS INITIAL.

    DO xstrlen( iv_message ) TIMES.
      lv_index = sy-index - 1.
      lv_hex = iv_message+lv_index(1).
      li_message->set_binary( lv_hex ).
      li_message_manager->send( li_message ).
    ENDDO.

  ENDMETHOD.
ENDCLASS.
