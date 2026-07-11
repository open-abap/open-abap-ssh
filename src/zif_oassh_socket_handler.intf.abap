INTERFACE zif_oassh_socket_handler
  PUBLIC.

* callbacks invoked by a zif_oassh_socket when the connection opens,
* delivers data, closes or errors. The transport layer implements this;
* both the APC adapter and the test mock drive it.
  METHODS on_open
    RAISING
      cx_static_check.
  METHODS on_message
    IMPORTING
      iv_data TYPE xstring
    RAISING
      cx_static_check.
  METHODS on_close.
  METHODS on_error.
  METHODS is_complete
    RETURNING
      VALUE(rv_complete) TYPE abap_bool.
ENDINTERFACE.
