CLASS zcl_oassh_socket_mock DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* in-memory zif_oassh_socket for tests. Bytes passed to send( ) are
* accumulated and readable via get_sent( ); inbound bytes are staged with
* set_replay( ) and handed out by the next read( ). An empty read with no
* staged bytes simulates a read timeout; set_closed( ) simulates the peer
* closing the connection or a transport error.

    INTERFACES zif_oassh_socket.

    METHODS set_replay
      IMPORTING
        iv_data TYPE xstring.
    METHODS set_closed.
    METHODS get_sent
      RETURNING
        VALUE(rv_data) TYPE xstring.
    METHODS is_connected
      RETURNING
        VALUE(rv_connected) TYPE abap_bool.
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA mv_sent      TYPE xstring.
    DATA mv_connected TYPE abap_bool.
    DATA mv_replay    TYPE xstring.
    DATA mv_closed    TYPE abap_bool.
ENDCLASS.



CLASS zcl_oassh_socket_mock IMPLEMENTATION.


  METHOD get_sent.
    rv_data = mv_sent.
  ENDMETHOD.


  METHOD is_connected.
    rv_connected = mv_connected.
  ENDMETHOD.


  METHOD set_replay.
    mv_replay = mv_replay && iv_data.
  ENDMETHOD.


  METHOD set_closed.
    mv_closed = abap_true.
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


  METHOD zif_oassh_socket~read.
* staged bytes are delivered in one piece; the SSH core reassembles packets
* from its stream buffer, so chunking granularity is irrelevant here
    rv_data = mv_replay.
    CLEAR mv_replay.
  ENDMETHOD.


  METHOD zif_oassh_socket~is_closed.
    rv_closed = mv_closed.
  ENDMETHOD.
ENDCLASS.
