CLASS lcl_handler DEFINITION FINAL.

  PUBLIC SECTION.
    INTERFACES zif_oassh_socket_handler.
    METHODS opened
      RETURNING VALUE(rv_opened) TYPE abap_bool.
    METHODS closed
      RETURNING VALUE(rv_closed) TYPE abap_bool.
    METHODS errored
      RETURNING VALUE(rv_errored) TYPE abap_bool.
    METHODS received
      RETURNING VALUE(rv_received) TYPE xstring.
  PRIVATE SECTION.
    DATA mv_opened   TYPE abap_bool.
    DATA mv_closed   TYPE abap_bool.
    DATA mv_errored  TYPE abap_bool.
    DATA mv_received TYPE xstring.
ENDCLASS.

CLASS lcl_handler IMPLEMENTATION.

  METHOD opened.
    rv_opened = mv_opened.
  ENDMETHOD.

  METHOD closed.
    rv_closed = mv_closed.
  ENDMETHOD.

  METHOD errored.
    rv_errored = mv_errored.
  ENDMETHOD.

  METHOD received.
    rv_received = mv_received.
  ENDMETHOD.

  METHOD zif_oassh_socket_handler~on_open.
    mv_opened = abap_true.
  ENDMETHOD.

  METHOD zif_oassh_socket_handler~on_message.
    mv_received = mv_received && iv_data.
  ENDMETHOD.

  METHOD zif_oassh_socket_handler~on_close.
    mv_closed = abap_true.
  ENDMETHOD.

  METHOD zif_oassh_socket_handler~on_error.
    mv_errored = abap_true.
  ENDMETHOD.

  METHOD zif_oassh_socket_handler~is_complete.
    rv_complete = mv_closed.
  ENDMETHOD.

ENDCLASS.


CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_mock    TYPE REF TO zcl_oassh_socket_mock.
    DATA mo_handler TYPE REF TO lcl_handler.
    DATA mi_socket  TYPE REF TO zif_oassh_socket.
    METHODS setup.
    METHODS connect FOR TESTING RAISING cx_static_check.
    METHODS send_accumulates FOR TESTING RAISING cx_static_check.
    METHODS events_reach_handler FOR TESTING RAISING cx_static_check.
    METHODS wait_replays FOR TESTING RAISING cx_static_check.
    METHODS close FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD setup.
    mo_mock = NEW zcl_oassh_socket_mock( ).
    mo_handler = NEW lcl_handler( ).
    mi_socket = mo_mock.
    mi_socket->set_handler( mo_handler ).
  ENDMETHOD.

  METHOD connect.

    cl_abap_unit_assert=>assert_false( mo_mock->is_connected( ) ).
    mi_socket->connect( ).
    cl_abap_unit_assert=>assert_true( mo_mock->is_connected( ) ).

  ENDMETHOD.

  METHOD send_accumulates.

    mi_socket->connect( ).
    mi_socket->send( 'AABB' ).
    mi_socket->send( 'CCDD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_mock->get_sent( )
      exp = 'AABBCCDD' ).

  ENDMETHOD.


  METHOD wait_replays.
    mo_mock->set_replay( 'AABBCCDD' ).
    mi_socket->wait( 1 ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_handler->received( )
      exp = 'AABBCCDD' ).
  ENDMETHOD.

  METHOD events_reach_handler.

    mo_mock->simulate_open( ).
    mo_mock->simulate_message( '1122' ).
    mo_mock->simulate_message( '3344' ).

    cl_abap_unit_assert=>assert_true( mo_handler->opened( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_handler->received( )
      exp = '11223344' ).

  ENDMETHOD.

  METHOD close.

    mi_socket->connect( ).
    mo_mock->simulate_close( ).

    cl_abap_unit_assert=>assert_true( mo_handler->closed( ) ).
    cl_abap_unit_assert=>assert_false( mo_mock->is_connected( ) ).

  ENDMETHOD.

ENDCLASS.
