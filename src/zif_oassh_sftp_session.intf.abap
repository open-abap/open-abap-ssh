INTERFACE zif_oassh_sftp_session
  PUBLIC.

* Reusable SFTP channel. Call sftp_open( ) once, run sequential sftp_*
* operations, then call sftp_close( ) and close( ). Result types are owned by
* zif_oassh_sftp_one_shot and referenced directly by both SFTP contracts.
  METHODS sftp_open
    IMPORTING
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING
      zcx_oassh_error.
  METHODS sftp_close
    IMPORTING
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING
      zcx_oassh_error.
  METHODS sftp_download
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rv_data)     TYPE xstring
    RAISING
      zcx_oassh_error.
  METHODS sftp_upload
    IMPORTING
      iv_path            TYPE string
      iv_data            TYPE xstring
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING
      zcx_oassh_error.
  METHODS sftp_stat
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rs_attrs)    TYPE zif_oassh_sftp_one_shot=>ty_attrs
    RAISING
      zcx_oassh_error.
  METHODS sftp_lstat
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rs_attrs)    TYPE zif_oassh_sftp_one_shot=>ty_attrs
    RAISING
      zcx_oassh_error.
  METHODS sftp_list
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rt_names)    TYPE zif_oassh_sftp_one_shot=>ty_names
    RAISING
      zcx_oassh_error.
  METHODS sftp_mkdir
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING zcx_oassh_error.
  METHODS sftp_rmdir
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING zcx_oassh_error.
  METHODS sftp_remove
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING zcx_oassh_error.
  METHODS sftp_rename
    IMPORTING
      iv_old_path        TYPE string
      iv_new_path        TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RAISING zcx_oassh_error.
  METHODS sftp_realpath
    IMPORTING
      iv_path                TYPE string
      iv_timeout_seconds     TYPE i DEFAULT 300
    RETURNING VALUE(rs_name) TYPE zif_oassh_sftp_one_shot=>ty_name
    RAISING zcx_oassh_error.
  METHODS get_disconnect_reason
    RETURNING
      VALUE(rv_reason) TYPE i.
  METHODS close.
ENDINTERFACE.
