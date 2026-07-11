INTERFACE zif_oassh_socket
  PUBLIC.

* abstraction over the TCP transport. The production implementation wraps
* ABAP Push Channels; the test implementation is an in-memory mock. Data
* arrives asynchronously through a zif_oassh_socket_handler.
  METHODS set_handler
    IMPORTING
      ii_handler TYPE REF TO zif_oassh_socket_handler.
  METHODS connect
    RAISING
      cx_static_check.
  METHODS send
    IMPORTING
      iv_data TYPE xstring
    RAISING
      cx_static_check.
  METHODS close.
  METHODS wait.
ENDINTERFACE.
