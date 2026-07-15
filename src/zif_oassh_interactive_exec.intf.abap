INTERFACE zif_oassh_interactive_exec
  PUBLIC.

* Interactive command channel. Call exec_open( ) once, exchange binary data
* with exec_write( ) and exec_read( ), then finish with exec_close( ). close( )
* closes the underlying SSH socket and remains the final cleanup operation.
  METHODS exec_open
    IMPORTING
      iv_command         TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING
      zcx_oassh_error.
  METHODS exec_write
    IMPORTING
      iv_data TYPE xstring
    RAISING
      zcx_oassh_error.
  METHODS exec_read
    IMPORTING
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rv_data)     TYPE xstring
    RAISING
      zcx_oassh_error.
  METHODS exec_eof
    RAISING
      zcx_oassh_error.
  METHODS exec_close
    IMPORTING
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING
      zcx_oassh_error.
  METHODS exec_is_closed
    RETURNING
      VALUE(rv_closed) TYPE abap_bool.
  METHODS get_stderr
    RETURNING
      VALUE(rv_output) TYPE string.
  METHODS get_exit_status
    RETURNING
      VALUE(rv_status) TYPE i.
  METHODS get_disconnect_reason
    RETURNING
      VALUE(rv_reason) TYPE i.
  METHODS close.
ENDINTERFACE.
