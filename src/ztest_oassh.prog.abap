REPORT ztest_oassh.

START-OF-SELECTION.
  PERFORM run.

FORM run RAISING cx_static_check.

  zcl_oassh=>connect(
    iv_host = 'github.com'
    iv_port = '22' ).

ENDFORM.
