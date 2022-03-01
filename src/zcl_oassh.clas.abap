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
    DATA mv_buffer TYPE xstring .
    DATA mv_state TYPE i .

    METHODS handle .
    METHODS send
      IMPORTING
        !iv_message TYPE xstring
      RAISING
        cx_apc_error .
ENDCLASS.



CLASS zcl_oassh IMPLEMENTATION.


  METHOD connect.

    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA ls_frame TYPE apc_tcp_frame.

    CREATE OBJECT lo_ssh.

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
    DATA lo_stream         TYPE REF TO zcl_oassh_stream.
    DATA lv_padding_length TYPE i.
    DATA lv_length         TYPE i.
    DATA ls_kexinit        TYPE zcl_oassh_message_20=>ty_data.

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

        IF xstrlen( mv_buffer ) > 4.
          CREATE OBJECT lo_stream EXPORTING iv_hex = mv_buffer.
          lv_length = lo_stream->uint32_decode( ).
          IF lo_stream->get_length( ) = lv_length.
* there is no MAC negotiated at this point in time
            lv_padding_length = lo_stream->take( 1 ).
            ls_kexinit = zcl_oassh_message_20=>parse( lo_stream ).
            lo_stream->take( lv_padding_length ).
            BREAK-POINT.
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

    TRY.
        lv_message = i_message->get_binary( ).
      CATCH cx_root.
    ENDTRY.
    mv_buffer = mv_buffer && lv_message.

    handle( ).

  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.
    DATA lv_xstr TYPE xstring.

    WRITE / 'on_open'.

* https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

    lv_xstr = cl_abap_codepage=>convert_to( 'SSH-2.0-abap' && cl_abap_char_utilities=>cr_lf ).

    send( lv_xstr ).

    mv_state = gc_state-protocol_version_exchange.

  ENDMETHOD.


  METHOD send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.
    DATA lv_index TYPE i.
    DATA lv_hex TYPE xstring.

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