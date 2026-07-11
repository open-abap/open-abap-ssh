CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh DEFINITION LOCAL FRIENDS ltcl_test.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS on_open_sends_version FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD on_open_sends_version.

    DATA lo_mock   TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh    TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.

    lo_mock = NEW zcl_oassh_socket_mock( ).
    li_socket = lo_mock.

    CREATE OBJECT lo_ssh
      EXPORTING
        ii_socket = li_socket.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

    lo_mock->simulate_open( ).

    " the client version string, SSH-2.0-abap followed by CR LF
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = '5353482D322E302D616261700D0A' ).

  ENDMETHOD.

ENDCLASS.
