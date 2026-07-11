REPORT ztest_oassh.

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
  lo_random = NEW zcl_oassh_random_fixed( ).
  lo_host_verifier = NEW lcl_accept_host( ).
  lo_ssh = zcl_oassh=>connect(
    iv_host          = 'github.com'
    iv_port          = '22'
    iv_user          = 'demo'
    iv_password      = 'demo'
    ii_random        = lo_random
    ii_host_verifier = lo_host_verifier ).
  lv_output = lo_ssh->execute( 'printf open-abap-ssh' ).
  ASSERT lv_output = 'open-abap-ssh'.
  ASSERT lo_ssh->get_exit_status( ) = 0.
  lo_ssh->close( ).

ENDFORM.
