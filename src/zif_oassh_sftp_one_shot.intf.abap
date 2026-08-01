INTERFACE zif_oassh_sftp_one_shot
  PUBLIC.

* One SFTP operation per SSH connection. Each sftp_* method owns the SFTP
* channel lifecycle. Call close( ) afterwards to close the underlying socket.
  TYPES ty_uint32 TYPE x LENGTH 4.
  TYPES ty_uint64 TYPE x LENGTH 8.
  TYPES:
    BEGIN OF ty_extension,
      extension_type TYPE xstring,
      extension_data TYPE xstring,
    END OF ty_extension.
  TYPES ty_extensions TYPE STANDARD TABLE OF ty_extension WITH EMPTY KEY.
  TYPES:
    BEGIN OF ty_attrs,
      flags           TYPE ty_uint32,
      has_size        TYPE abap_bool,
      size            TYPE ty_uint64,
      has_uid_gid     TYPE abap_bool,
      uid             TYPE ty_uint32,
      gid             TYPE ty_uint32,
      has_permissions TYPE abap_bool,
      permissions     TYPE ty_uint32,
      has_acmodtime   TYPE abap_bool,
      atime           TYPE ty_uint32,
      mtime           TYPE ty_uint32,
      extensions      TYPE ty_extensions,
    END OF ty_attrs.
  TYPES:
    BEGIN OF ty_name,
      filename TYPE xstring,
      longname TYPE xstring,
      attrs    TYPE ty_attrs,
    END OF ty_name.
  TYPES ty_names TYPE STANDARD TABLE OF ty_name WITH EMPTY KEY.
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
      VALUE(rs_attrs)    TYPE ty_attrs
    RAISING
      zcx_oassh_error.
  METHODS sftp_lstat
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rs_attrs)    TYPE ty_attrs
    RAISING
      zcx_oassh_error.
  METHODS sftp_list
    IMPORTING
      iv_path            TYPE string
      iv_timeout_seconds TYPE i DEFAULT 300
    RETURNING
      VALUE(rt_names)    TYPE ty_names
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
    RETURNING VALUE(rs_name) TYPE ty_name
    RAISING zcx_oassh_error.
  METHODS get_disconnect_reason
    RETURNING
      VALUE(rv_reason) TYPE i.
  METHODS close.
ENDINTERFACE.
