CLASS zcl_oassh DEFINITION
  PUBLIC
  CREATE PRIVATE .

  PUBLIC SECTION.

    INTERFACES if_apc_wsp_event_handler .

    CLASS-METHODS connect
      IMPORTING
        !iv_host TYPE string
        !iv_port TYPE string
      RAISING
        cx_static_check .
  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      BEGIN OF gc_state,
        protocol_version_exchange TYPE i VALUE 1,
        key_exchange              TYPE i VALUE 2,
      END OF gc_state .
    DATA mi_client TYPE REF TO if_apc_wsp_client .
    DATA mo_stream TYPE REF TO zcl_oassh_stream .
    DATA mv_state TYPE i .

    METHODS handle
      RAISING
        cx_apc_error .
    METHODS send
      IMPORTING
        !iv_message TYPE xstring
      RAISING
        cx_apc_error .
ENDCLASS.



CLASS ZCL_OASSH IMPLEMENTATION.


  METHOD connect.

    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA ls_frame TYPE if_abap_channel_types=>ty_apc_tcp_frame.

    CREATE OBJECT lo_ssh.

    CREATE OBJECT lo_ssh->mo_stream.

    ls_frame-frame_type   = if_apc_tcp_frame_types=>co_frame_type_fixed_length.
    ls_frame-fixed_length = 1.

    lo_ssh->mi_client = cl_apc_tcp_client_manager=>create(
      i_host          = iv_host
      i_port          = iv_port
      i_frame         = ls_frame
      i_event_handler = lo_ssh ).

    lo_ssh->mi_client->connect( ).

  ENDMETHOD.


  METHOD handle.

    DATA lv_remote_version TYPE string.
    DATA lv_padding_length TYPE i.
    DATA lv_length         TYPE i.
    DATA ls_kexinit        TYPE zcl_oassh_message_20=>ty_data.

    CASE mv_state.
      WHEN gc_state-protocol_version_exchange.
        IF mo_stream->get( ) CP |*{ cl_abap_codepage=>convert_to( |{ cl_abap_char_utilities=>cr_lf }| ) }|.
          lv_remote_version = cl_abap_codepage=>convert_from( mo_stream->get( ) ).
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
            send( zcl_oassh_message_20=>serialize( ls_kexinit )->get( ) ).
          ENDIF.
        ENDIF.

    ENDCASE.

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
    DATA lv_message TYPE xstring.
    DATA lx_error   TYPE REF TO cx_root.

    TRY.
        lv_message = i_message->get_binary( ).
        mo_stream->append( lv_message ).
        handle( ).
      CATCH cx_root INTO lx_error.
        BREAK-POINT.
    ENDTRY.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.
    DATA lv_xstr TYPE xstring.
    BREAK-POINT.

    WRITE / 'on_open'.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    lv_xstr = cl_abap_codepage=>convert_to( 'SSH-2.0-abap' && cl_abap_char_utilities=>cr_lf ).

    TRY.
        send( lv_xstr ).
      CATCH cx_apc_error.
        ASSERT 1 = 2.
    ENDTRY.

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.


  METHOD send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.
    DATA lv_index           TYPE i.
    DATA lv_hex             TYPE xstring.

    li_message_manager ?= mi_client->get_message_manager( ).

    li_message = li_message_manager->create_message( ).

    ASSERT iv_message IS NOT INITIAL.

    DO xstrlen( iv_message ) TIMES.
      lv_index = sy-index - 1.
      lv_hex = iv_message+lv_index(1).
      li_message->set_binary( lv_hex ).
      li_message_manager->send( li_message ).
    ENDDO.

  ENDMETHOD.
ENDCLASS.
