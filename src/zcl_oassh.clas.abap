class ZCL_OASSH definition
  public
  create private .

public section.

  interfaces IF_APC_WSP_EVENT_HANDLER .
  interfaces IF_APC_WSP_EVENT_HANDLER_BASE .

  class-methods CONNECT
    importing
      !IV_HOST type STRING
      !IV_PORT type STRING
    raising
      CX_STATIC_CHECK .
  PROTECTED SECTION.
PRIVATE SECTION.

  CONSTANTS:
    BEGIN OF gc_state,
      protocol_version_exchange TYPE i VALUE 1,
      key_exchange              TYPE i VALUE 2,
    END OF gc_state .
  DATA mi_client TYPE REF TO if_apc_wsp_client .
  DATA mv_buffer TYPE xstring .
  DATA mv_state TYPE i .

  METHODS handle .
  METHODS send
    IMPORTING
      !iv_message TYPE xstring
    RAISING
      cx_apc_error .
ENDCLASS.



CLASS ZCL_OASSH IMPLEMENTATION.


  METHOD connect.

    DATA(lo_ssh) = NEW zcl_oassh( ).

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


  METHOD HANDLE.

    DATA lv_remote_version TYPE string.

    CASE mv_state.
      WHEN gc_state-protocol_version_exchange.
        IF mv_buffer CP |*{ cl_abap_codepage=>convert_to( |{ cl_abap_char_utilities=>cr_lf }| ) }|.
          lv_remote_version = cl_abap_codepage=>convert_from( mv_buffer ).
          CLEAR mv_buffer.
          mv_state = gc_state-key_exchange.
        ENDIF.
      WHEN gc_state-key_exchange.
* todo, check buffer contains a full packet, and return the packet payload
* https://datatracker.ietf.org/doc/html/rfc4253#section-7
* name-lists of supported algorithms
    ENDCASE.

  ENDMETHOD.


  METHOD IF_APC_WSP_EVENT_HANDLER~ON_CLOSE.
    BREAK-POINT.
    WRITE / 'on_close'.
  ENDMETHOD.


  METHOD IF_APC_WSP_EVENT_HANDLER~ON_ERROR.
    BREAK-POINT.
    WRITE / 'on_error'.
  ENDMETHOD.


  METHOD IF_APC_WSP_EVENT_HANDLER~ON_MESSAGE.
    DATA lv_message TYPE xstring.

    TRY.
        lv_message = i_message->get_binary( ).
      CATCH cx_root.
    ENDTRY.
    mv_buffer = mv_buffer && lv_message.

    handle( ).

  ENDMETHOD.


  METHOD IF_APC_WSP_EVENT_HANDLER~ON_OPEN.
    DATA lv_xstr TYPE xstring.

    WRITE / 'on_open'.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    lv_xstr = cl_abap_codepage=>convert_to( 'SSH-2.0-abap' && cl_abap_char_utilities=>cr_lf ).

    send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.


  METHOD SEND.

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
