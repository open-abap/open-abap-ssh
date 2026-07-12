CLASS zcl_oassh_socket_mock DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* in-memory zif_oassh_socket for tests. Bytes passed to send( ) are
* accumulated and readable via get_sent( ); inbound events are injected
* with the simulate_* methods, which drive the registered handler.

    INTERFACES zif_oassh_socket.

    METHODS simulate_open
      RAISING
        cx_static_check.
    METHODS simulate_message
      IMPORTING
        iv_data TYPE xstring
      RAISING
        cx_static_check.
    METHODS simulate_close.
    METHODS simulate_error.
    METHODS set_replay
      IMPORTING
        iv_data TYPE xstring.
    METHODS get_sent
      RETURNING
        VALUE(rv_data) TYPE xstring.
    METHODS is_connected
      RETURNING
        VALUE(rv_connected) TYPE abap_bool.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mi_handler   TYPE REF TO zif_oassh_socket_handler.
    DATA mv_sent      TYPE xstring.
    DATA mv_connected TYPE abap_bool.
    DATA mv_replay    TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_socket_mock IMPLEMENTATION.


  METHOD get_sent.
    rv_data = mv_sent.
  ENDMETHOD.


  METHOD is_connected.
    rv_connected = mv_connected.
  ENDMETHOD.


  METHOD set_replay.
    mv_replay = iv_data.
  ENDMETHOD.


  METHOD simulate_close.
    mv_connected = abap_false.
    IF mi_handler IS BOUND.
      mi_handler->on_close( ).
    ENDIF.
  ENDMETHOD.


  METHOD simulate_error.
    IF mi_handler IS BOUND.
      mi_handler->on_error( ).
    ENDIF.
  ENDMETHOD.


  METHOD simulate_message.
    ASSERT mi_handler IS BOUND.
    mi_handler->on_message( iv_data ).
  ENDMETHOD.


  METHOD simulate_open.
    ASSERT mi_handler IS BOUND.
    mi_handler->on_open( ).
  ENDMETHOD.


  METHOD zif_oassh_socket~connect.
    mv_connected = abap_true.
  ENDMETHOD.


  METHOD zif_oassh_socket~close.
    mv_connected = abap_false.
  ENDMETHOD.


  METHOD zif_oassh_socket~send.
    ASSERT mv_connected = abap_true.
    mv_sent = mv_sent && iv_data.
  ENDMETHOD.


  METHOD zif_oassh_socket~wait.
    DATA lv_replay TYPE xstring.
    IF mv_replay IS INITIAL OR mi_handler IS NOT BOUND.
      RETURN.
    ENDIF.
* Clear before dispatch so a callback cannot replay the same stream twice.
    lv_replay = mv_replay.
    CLEAR mv_replay.
    TRY.
        mi_handler->on_message( lv_replay ).
      CATCH cx_static_check.
        ASSERT 1 = 2.
    ENDTRY.
  ENDMETHOD.


  METHOD zif_oassh_socket~set_handler.
    mi_handler = ii_handler.
  ENDMETHOD.
ENDCLASS.
