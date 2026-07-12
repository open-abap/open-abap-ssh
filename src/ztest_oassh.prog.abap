REPORT ztest_oassh.

TYPES ty_host TYPE c LENGTH 255.
TYPES ty_port TYPE c LENGTH 5.
TYPES ty_user TYPE c LENGTH 64.
TYPES ty_password TYPE c LENGTH 64.
TYPES ty_command TYPE c LENGTH 255.

PARAMETERS p_host TYPE ty_host LOWER CASE DEFAULT 'oassh-test'.
PARAMETERS p_port TYPE ty_port DEFAULT '2222'.
PARAMETERS p_user TYPE ty_user LOWER CASE DEFAULT 'demo'.
PARAMETERS p_pass TYPE ty_password LOWER CASE DEFAULT 'demo' NO-DISPLAY.
PARAMETERS p_cmd TYPE ty_command LOWER CASE DEFAULT 'printf open-abap-ssh'.
PARAMETERS p_expect TYPE ty_command LOWER CASE DEFAULT 'open-abap-ssh'.
PARAMETERS p_tmout TYPE i DEFAULT 300.

CLASS lcl_accept_host DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
ENDCLASS.

CLASS lcl_accept_host IMPLEMENTATION.
  METHOD zif_oassh_host_verifier~verify.
* Demo only: production callers must pin or otherwise validate iv_host_key.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  PERFORM run.

FORM run RAISING cx_static_check.

  DATA lo_random TYPE REF TO zif_oassh_random.
  DATA lo_host_verifier TYPE REF TO zif_oassh_host_verifier.
  DATA lo_ssh TYPE REF TO zcl_oassh.
  DATA lv_output TYPE string.
  DATA lv_expected TYPE string.
  lo_random = NEW zcl_oassh_random_fixed( ).
  lo_host_verifier = NEW lcl_accept_host( ).
  lo_ssh = zcl_oassh=>connect(
    iv_host          = CONV #( p_host )
    iv_port          = CONV #( p_port )
    iv_user          = CONV #( p_user )
    iv_password      = CONV #( p_pass )
    ii_random        = lo_random
    ii_host_verifier = lo_host_verifier ).
  lv_output = lo_ssh->execute(
    iv_command         = CONV #( p_cmd )
    iv_timeout_seconds = p_tmout ).
  lv_expected = p_expect.
  WRITE / lv_output.
  ASSERT lv_output = lv_expected.
  ASSERT lo_ssh->get_exit_status( ) = 0.
  lo_ssh->close( ).

ENDFORM.
