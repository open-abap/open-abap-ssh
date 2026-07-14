CLASS lcx_previous DEFINITION
  INHERITING FROM cx_static_check.
ENDCLASS.

CLASS ltcl_test DEFINITION FINAL
  FOR TESTING
  RISK LEVEL HARMLESS
  DURATION SHORT.
  PRIVATE SECTION.
    METHODS message_key FOR TESTING RAISING cx_static_check.
    METHODS sftp_message FOR TESTING RAISING cx_static_check.
    METHODS previous FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS lcx_previous IMPLEMENTATION.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD message_key.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    TRY.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e001(zoassh).
      CATCH zcx_oassh_error INTO lx_error.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->if_t100_message~t100key-msgno
      exp = '001' ).
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->if_t100_message~t100key-msgid
      exp = 'ZOASSH' ).
  ENDMETHOD.


  METHOD sftp_message.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    TRY.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e012(zoassh) WITH '4'
          EXPORTING
            iv_sftp_status = 4.
      CATCH zcx_oassh_error INTO lx_error.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->if_t100_message~t100key-msgno
      exp = '012' ).
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->get_sftp_status( )
      exp = 4 ).
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->get_text( )
      exp = 'SFTP server returned status 4' ).
  ENDMETHOD.


  METHOD previous.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lx_previous TYPE REF TO lcx_previous.
    lx_previous = NEW #( ).
    TRY.
        RAISE EXCEPTION TYPE zcx_oassh_error
          MESSAGE e013(zoassh)
          EXPORTING
            previous = lx_previous.
      CATCH zcx_oassh_error INTO lx_error.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lx_error->previous
      exp = lx_previous ).
  ENDMETHOD.
ENDCLASS.
