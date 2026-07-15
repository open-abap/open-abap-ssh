REPORT zoassh_example_sftp.

* -----------------------------------------------------------------------------
* open-abap-ssh example: connect to an SFTP server, list a directory, and
* download one file, showing the result on the ABAP list.
*
* Copy this report into a system that has open-abap-ssh installed, activate it,
* and run it. Fill in the host, port, user, and password on the selection
* screen. The SAP system must permit outbound TCP to the SSH host/port through
* ABAP Push Channels (APC).
*
* SECURITY: lcl_accept_host below trusts every server host key. That is safe
* only against a host you already control in an isolated test. In production,
* implement zif_oassh_host_verifier to pin or otherwise validate the host key,
* and use that verifier instead of lcl_accept_host.
* -----------------------------------------------------------------------------

* Defaults target the public Rebex test server (https://test.rebex.net), a
* read-only SFTP server useful for a quick end-to-end check. Its root holds a
* small readme.txt alongside a pub/ folder.
PARAMETERS p_host TYPE string LOWER CASE OBLIGATORY DEFAULT 'test.rebex.net'.
PARAMETERS p_port TYPE string DEFAULT '22'.
PARAMETERS p_user TYPE string LOWER CASE OBLIGATORY DEFAULT 'demo'.
PARAMETERS p_pass TYPE string LOWER CASE OBLIGATORY DEFAULT 'password'.
PARAMETERS p_dir  TYPE string LOWER CASE DEFAULT '/'.
PARAMETERS p_file TYPE string LOWER CASE DEFAULT '/readme.txt'.
PARAMETERS p_tmout TYPE i DEFAULT 60.

CLASS lcl_accept_host DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
ENDCLASS.

CLASS lcl_accept_host IMPLEMENTATION.
  METHOD zif_oassh_host_verifier~verify.
* Demo only: production callers must validate iv_host/iv_port with iv_host_key.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  PERFORM run.

FORM run.

  DATA lo_host_verifier TYPE REF TO zif_oassh_host_verifier.
  DATA li_sftp          TYPE REF TO zif_oassh_sftp_session.
  DATA lt_names         TYPE zif_oassh_sftp_session=>ty_names.
  DATA lv_filename      TYPE string.
  DATA lv_data          TYPE xstring.
  DATA lv_preview       TYPE string.
  DATA lx_error         TYPE REF TO cx_static_check.

  lo_host_verifier = NEW lcl_accept_host( ).

* One authenticated connection runs both operations: sftp_open performs the
* channel, subsystem, and INIT/VERSION handshake once, then the listing and
* download reuse that single SFTP session until sftp_close.
  TRY.
* ii_random is optional on SAP: zcl_oassh defaults to zcl_oassh_random_secure,
* which draws from the kernel-backed secure random source.
      li_sftp = zcl_oassh=>connect(
        iv_host          = p_host
        iv_port          = p_port
        iv_user          = p_user
        iv_password      = p_pass
        ii_host_verifier = lo_host_verifier ).
      TRY.
          li_sftp->sftp_open( p_tmout ).

* --- list a directory -----------------------------------------------------
          lt_names = li_sftp->sftp_list(
            iv_path            = p_dir
            iv_timeout_seconds = p_tmout ).

* --- download a file ------------------------------------------------------
          lv_data = li_sftp->sftp_download(
            iv_path            = p_file
            iv_timeout_seconds = p_tmout ).

          li_sftp->sftp_close( p_tmout ).
        CLEANUP.
          li_sftp->close( ).
      ENDTRY.
      li_sftp->close( ).

      WRITE: / 'listing of', p_dir.
      SKIP.
      LOOP AT lt_names INTO DATA(ls_name).
* SFTP file names are raw bytes on the wire; decode them as UTF-8 for display.
        lv_filename = zcl_oassh_ascii=>from_xstring_text( ls_name-filename ).
        WRITE / lv_filename.
      ENDLOOP.

      SKIP.
      WRITE: / 'downloaded', p_file, '-', xstrlen( lv_data ), 'bytes'.
* The download is binary-safe; render a text preview only for display.
      lv_preview = zcl_oassh_ascii=>from_xstring_text( lv_data ).
      IF lv_preview IS NOT INITIAL.
        SKIP.
        WRITE / 'content:'.
        WRITE / lv_preview.
      ENDIF.

    CATCH cx_static_check INTO lx_error.
      WRITE: / 'SFTP error:', lx_error->get_text( ).
  ENDTRY.

ENDFORM.
