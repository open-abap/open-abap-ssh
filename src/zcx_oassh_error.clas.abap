CLASS zcx_oassh_error DEFINITION
  PUBLIC
  INHERITING FROM cx_static_check
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES if_t100_message.
    INTERFACES if_t100_dyn_msg.

    METHODS constructor
      IMPORTING
        textid LIKE if_t100_message=>t100key OPTIONAL
        previous LIKE previous OPTIONAL
        iv_sftp_status TYPE i DEFAULT -1.
    METHODS get_sftp_status
      RETURNING
        VALUE(rv_status) TYPE i.

  PRIVATE SECTION.
    DATA mv_sftp_status TYPE i.
ENDCLASS.


CLASS zcx_oassh_error IMPLEMENTATION.
  METHOD constructor.
    super->constructor( previous = previous ).
    CLEAR me->textid.
    IF textid IS INITIAL.
      if_t100_message~t100key = if_t100_message=>default_textid.
    ELSE.
      if_t100_message~t100key = textid.
    ENDIF.
    mv_sftp_status = iv_sftp_status.
  ENDMETHOD.

  METHOD get_sftp_status.
    rv_status = mv_sftp_status.
  ENDMETHOD.
ENDCLASS.
