CLASS zcl_abapgit_ssh DEFINITION PUBLIC CREATE PRIVATE.
  PUBLIC SECTION.
    INTERFACES if_apc_wsp_event_handler.
    CLASS-METHODS connect
      IMPORTING
        iv_host          TYPE string
        iv_port          TYPE string
      RAISING
        cx_static_check.
  PROTECTED SECTION.
  PRIVATE SECTION.
    DATA mi_client TYPE REF TO if_apc_wsp_client.
    DATA mv_on_message TYPE xstring.
    METHODS send
      IMPORTING
        iv_message TYPE xstring
      RAISING
        cx_apc_error.
ENDCLASS.



CLASS ZCL_ABAPGIT_SSH IMPLEMENTATION.


  METHOD connect.
    DATA ls_frame TYPE if_abap_channel_types=>ty_apc_tcp_frame.

    DATA(lo_ssh) = NEW zcl_abapgit_ssh( ).

* todo, set ls_frame

    lo_ssh->mi_client = cl_apc_tcp_client_manager=>create(
      i_host          = iv_host
      i_port          = iv_port
      i_frame         = ls_frame
      i_event_handler = lo_ssh ).

    lo_ssh->mi_client->connect( ).

  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_close.
    WRITE / 'on_close'.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_error.
    WRITE / 'on_error'.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_message.
    WRITE / 'on_message, received:'.
    TRY.
        mv_on_message = i_message->get_binary( ).
      CATCH cx_root.
    ENDTRY.
    WRITE / mv_on_message.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.
    WRITE / 'on_open'.
  ENDMETHOD.


  METHOD send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.

    li_message_manager ?= mi_client->get_message_manager( ).
    li_message = li_message_manager->create_message( ).
    li_message->set_binary( iv_message ).
    li_message_manager->send( li_message ).

    WAIT FOR PUSH CHANNELS
      UNTIL mv_on_message IS NOT INITIAL
      UP TO 10 SECONDS.

  ENDMETHOD.
ENDCLASS.
