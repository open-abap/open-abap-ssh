REPORT zoassh_example_exec.

* -----------------------------------------------------------------------------
* open-abap-ssh example: connect to an SSH server, run one command, and show
* its stdout, stderr, and exit status on the ABAP list.
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
* read-only virtual shell useful for a quick end-to-end check. Its shell lacks
* printf and is not a real OS, so the command uses echo; echo appends a
* trailing newline, so stdout comes back as 'open-abap-ssh' followed by LF.
PARAMETERS p_host TYPE string LOWER CASE OBLIGATORY DEFAULT 'test.rebex.net'.
PARAMETERS p_port TYPE string DEFAULT '22'.
PARAMETERS p_user TYPE string LOWER CASE OBLIGATORY DEFAULT 'demo'.
PARAMETERS p_pass TYPE string LOWER CASE OBLIGATORY DEFAULT 'password'.
PARAMETERS p_cmd  TYPE string LOWER CASE DEFAULT 'echo open-abap-ssh'.
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
  DATA lo_ssh           TYPE REF TO zcl_oassh.
  DATA lv_stdout        TYPE string.
  DATA lv_stderr        TYPE string.
  DATA lv_exit_status   TYPE i.
  DATA lx_error         TYPE REF TO cx_static_check.

  lo_host_verifier = NEW lcl_accept_host( ).

  TRY.
* ii_random is optional on SAP: zcl_oassh defaults to zcl_oassh_random_secure,
* which draws from the kernel-backed secure random source.
      lo_ssh = zcl_oassh=>connect(
        iv_host          = p_host
        iv_port          = p_port
        iv_user          = p_user
        iv_password      = p_pass
        ii_host_verifier = lo_host_verifier ).

      TRY.
          lv_stdout = lo_ssh->execute(
            iv_command         = p_cmd
            iv_timeout_seconds = p_tmout ).
          lv_stderr      = lo_ssh->get_stderr( ).
          lv_exit_status = lo_ssh->get_exit_status( ).
        CLEANUP.
          lo_ssh->close( ).
      ENDTRY.
      lo_ssh->close( ).

      WRITE: / 'exit status:', lv_exit_status.
      SKIP.
      WRITE / 'stdout:'.
      WRITE / lv_stdout.
      IF lv_stderr IS NOT INITIAL.
        SKIP.
        WRITE / 'stderr:'.
        WRITE / lv_stderr.
      ENDIF.

    CATCH cx_static_check INTO lx_error.
      WRITE: / 'SSH error:', lx_error->get_text( ).
  ENDTRY.

ENDFORM.
