INTERFACE zif_oassh_socket
  PUBLIC.

* abstraction over the TCP transport. The production implementation wraps
* ABAP Push Channels; the test implementation is an in-memory mock. The SSH
* core pulls inbound bytes with read( ), which blocks until data arrives,
* the timeout expires or the peer closes the connection. An empty read
* result means timeout when is_closed( ) is abap_false, otherwise the
* transport is gone (closed by the peer or failed).
  METHODS connect
    RAISING
      zcx_oassh_error.
  METHODS send
    IMPORTING
      iv_data TYPE xstring
    RAISING
      zcx_oassh_error.
  METHODS read
    IMPORTING
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rv_data)     TYPE xstring
    RAISING
      zcx_oassh_error.
  METHODS is_closed
    RETURNING
      VALUE(rv_closed) TYPE abap_bool.
  METHODS close.
ENDINTERFACE.
