CLASS zcl_oassh_socket_apc DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* zif_oassh_socket implementation on top of ABAP Push Channels (APC). This
* is the only place in the library that references the SAP standard APC
* classes; the SSH core talks to zif_oassh_socket only. The APC event
* callbacks just buffer inbound bytes and record a close; read( ) waits for
* push channels and hands the buffer to the SSH core.

    INTERFACES zif_oassh_socket.
    INTERFACES if_apc_wsp_event_handler.

    METHODS constructor
      IMPORTING
        iv_host   TYPE string
        iv_port   TYPE string
        iv_ssl_id TYPE ssfapplssl OPTIONAL.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mv_host   TYPE string.
    DATA mv_port   TYPE string.
    DATA mv_ssl_id TYPE ssfapplssl.
    DATA mi_client TYPE REF TO if_apc_wsp_client.
    DATA mv_buffer TYPE xstring.
    DATA mv_closed TYPE abap_bool.
ENDCLASS.



CLASS zcl_oassh_socket_apc IMPLEMENTATION.


  METHOD constructor.
    mv_host = iv_host.
    mv_port = iv_port.
    mv_ssl_id = iv_ssl_id.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_close.
    mv_closed = abap_true.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_error.
    mv_closed = abap_true.
  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_message.

    DATA lx_error TYPE REF TO cx_root.

    TRY.
        mv_buffer = mv_buffer && i_message->get_binary( ).
      CATCH cx_root INTO lx_error.
* an unreadable frame is unrecoverable for a byte-stream transport
        mv_closed = abap_true.
    ENDTRY.

  ENDMETHOD.


  METHOD if_apc_wsp_event_handler~on_open.
    RETURN.
  ENDMETHOD.


  METHOD zif_oassh_socket~connect.

    DATA ls_frame TYPE apc_tcp_frame.
    DATA lx_error TYPE REF TO cx_static_check.

* SSH has no fixed record length, so read one byte at a time and let the
* SSH core reassemble the version line and binary packets
    ls_frame-frame_type   = if_apc_tcp_frame_types=>co_frame_type_fixed_length.
    ls_frame-fixed_length = 1.

* i_ssl_id selects an SSL client identity from STRUST for a TLS-wrapped TCP
* connection. Empty maps to SPACE, which leaves the connection as plain TCP.
    TRY.
        mi_client = cl_apc_tcp_client_manager=>create(
          i_host          = mv_host
          i_port          = mv_port
          i_frame         = ls_frame
          i_ssl_id        = mv_ssl_id
          i_event_handler = me ).

        mi_client->connect( ).
      CATCH cx_static_check INTO lx_error.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e013(zoassh) WITH lx_error->get_text( )
          EXPORTING
            previous = lx_error.
    ENDTRY.

  ENDMETHOD.


  METHOD zif_oassh_socket~close.
    DATA lx_error TYPE REF TO cx_apc_error.
    IF mi_client IS BOUND.
      TRY.
          mi_client->close( ).
        CATCH cx_apc_error INTO lx_error.
          RETURN.
      ENDTRY.
    ENDIF.
  ENDMETHOD.


  METHOD zif_oassh_socket~send.

    DATA li_message_manager TYPE REF TO if_apc_wsp_message_manager.
    DATA li_message         TYPE REF TO if_apc_wsp_message.
    DATA lx_error           TYPE REF TO cx_static_check.

    ASSERT iv_data IS NOT INITIAL.

    TRY.
        li_message_manager ?= mi_client->get_message_manager( ).
        li_message = li_message_manager->create_message( ).
* SAP's APC TCP client API accepts a complete binary frame. SSH packets are
* bounded below APC's frame ceiling, so send once instead of issuing one APC
* message per byte.
        li_message->set_binary( iv_data ).
        li_message_manager->send( li_message ).
      CATCH cx_static_check INTO lx_error.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e013(zoassh) WITH lx_error->get_text( )
          EXPORTING
            previous = lx_error.
    ENDTRY.

  ENDMETHOD.


  METHOD zif_oassh_socket~read.
* APC events are delivered only while the ABAP session is idle or explicitly
* waiting for push channels. Generic WAIT UNTIL is not sufficient on ECC.
    ASSERT iv_timeout_seconds > 0.
    IF mv_buffer IS INITIAL AND mv_closed = abap_false.
      WAIT FOR PUSH CHANNELS
        UNTIL mv_buffer IS NOT INITIAL OR mv_closed = abap_true
        UP TO iv_timeout_seconds SECONDS.
    ENDIF.
    rv_data = mv_buffer.
    CLEAR mv_buffer.
  ENDMETHOD.


  METHOD zif_oassh_socket~is_closed.
    rv_closed = mv_closed.
  ENDMETHOD.
ENDCLASS.
