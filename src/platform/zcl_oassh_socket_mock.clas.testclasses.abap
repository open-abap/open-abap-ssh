CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_mock   TYPE REF TO zcl_oassh_socket_mock.
    DATA mi_socket TYPE REF TO zif_oassh_socket.
    METHODS setup.
    METHODS connect FOR TESTING RAISING cx_static_check.
    METHODS send_accumulates FOR TESTING RAISING cx_static_check.
    METHODS read_returns_replay FOR TESTING RAISING cx_static_check.
    METHODS empty_read_is_timeout FOR TESTING RAISING cx_static_check.
    METHODS closed FOR TESTING RAISING cx_static_check.
    METHODS close FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD setup.
    mo_mock = NEW zcl_oassh_socket_mock( ).
    mi_socket = mo_mock.
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


  METHOD read_returns_replay.
    mo_mock->set_replay( 'AABB' ).
    mo_mock->set_replay( 'CCDD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mi_socket->read( 1 )
      exp = 'AABBCCDD' ).
    cl_abap_unit_assert=>assert_initial( mi_socket->read( 1 ) ).
  ENDMETHOD.


  METHOD empty_read_is_timeout.
* an empty read while is_closed( ) is false is how the mock simulates a
* read timeout
    cl_abap_unit_assert=>assert_initial( mi_socket->read( 1 ) ).
    cl_abap_unit_assert=>assert_false( mi_socket->is_closed( ) ).
  ENDMETHOD.


  METHOD closed.

    cl_abap_unit_assert=>assert_false( mi_socket->is_closed( ) ).
    mo_mock->set_closed( ).

    cl_abap_unit_assert=>assert_true( mi_socket->is_closed( ) ).
    cl_abap_unit_assert=>assert_initial( mi_socket->read( 1 ) ).

  ENDMETHOD.

  METHOD close.

    mi_socket->connect( ).
    mi_socket->close( ).

    cl_abap_unit_assert=>assert_false( mo_mock->is_connected( ) ).

  ENDMETHOD.

ENDCLASS.
