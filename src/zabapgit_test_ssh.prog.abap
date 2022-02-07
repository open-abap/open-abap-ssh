REPORT zabapgit_test_ssh.

START-OF-SELECTION.
  PERFORM run.

FORM run.

  zcl_abapgit_ssh=>connect(
    iv_host = 'github.com'
    iv_port = '22' ).

ENDFORM.
