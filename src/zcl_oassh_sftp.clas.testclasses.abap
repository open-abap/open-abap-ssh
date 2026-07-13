CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh_sftp DEFINITION LOCAL FRIENDS ltcl_test.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    DATA mo_sftp TYPE REF TO zcl_oassh_sftp.
    METHODS setup.
    METHODS init_wire FOR TESTING RAISING cx_static_check.
    METHODS version_plain FOR TESTING RAISING cx_static_check.
    METHODS version_extensions FOR TESTING RAISING cx_static_check.
    METHODS version_fragmented FOR TESTING RAISING cx_static_check.
    METHODS two_responses FOR TESTING RAISING cx_static_check.
    METHODS invalid_lengths FOR TESTING RAISING cx_static_check.
    METHODS response_id_mismatch FOR TESTING RAISING cx_static_check.
    METHODS unknown_response FOR TESTING RAISING cx_static_check.
    METHODS version_six FOR TESTING RAISING cx_static_check.
    METHODS truncated_extension FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD setup.
    mo_sftp = NEW #( ).
  ENDMETHOD.


  METHOD init_wire.
* Section 3 length covers type + body; INIT is type 1 and uint32 version 3.
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->start( )
      exp = '000000050100000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-version_pending ).
  ENDMETHOD.


  METHOD version_plain.
    mo_sftp->start( ).
    mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_version( )
      exp = 3 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-ready ).
  ENDMETHOD.


  METHOD version_extensions.
* VERSION extension data is a sequence of two-string pairs; empty data is legal.
    DATA lv_packet TYPE xstring.
    mo_sftp->start( ).
    lv_packet = '0000001902000000030000000C706F7369782D72656E616D6500000000'.
    mo_sftp->receive( lv_packet ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_version( )
      exp = 3 ).
  ENDMETHOD.


  METHOD version_fragmented.
    mo_sftp->start( ).
    mo_sftp->receive( '0000000502' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-version_pending ).
    mo_sftp->receive( '00000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-ready ).
  ENDMETHOD.


  METHOD two_responses.
* Multiple requests may be outstanding and their complete responses may share
* one CHANNEL_DATA chunk. Both ids must be recognized and consumed.
    DATA lv_request TYPE xstring.
    DATA lv_responses TYPE xstring.
    mo_sftp->start( ).
    mo_sftp->receive( '000000050200000003' ).
    lv_request = mo_sftp->build_request(
      iv_type = '03'
      iv_body = 'AA' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_request
      exp = '000000060300000001AA' ).
    lv_request = mo_sftp->build_request(
      iv_type = '11'
      iv_body = 'BB' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_request
      exp = '000000061100000002BB' ).
    lv_responses = '000000116500000001000000000000000000000000'.
    lv_responses = lv_responses && '00000009690000000200000000'.
    mo_sftp->receive( lv_responses ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->mv_response_count
      exp = 2 ).
    cl_abap_unit_assert=>assert_initial( mo_sftp->mt_request_ids ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->mv_last_response_type
      exp = '69' ).
  ENDMETHOD.


  METHOD invalid_lengths.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    mo_sftp->start( ).
    TRY.
        mo_sftp->receive( '00000000' ).
        cl_abap_unit_assert=>fail( 'zero SFTP length accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.

    mo_sftp = NEW #( ).
    mo_sftp->start( ).
    TRY.
        mo_sftp->receive( '00040001' ).
        cl_abap_unit_assert=>fail( 'oversized SFTP length accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD response_id_mismatch.
    DATA lv_request TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    mo_sftp->start( ).
    mo_sftp->receive( '000000050200000003' ).
    lv_request = mo_sftp->build_request(
      iv_type = '03'
      iv_body = 'AA' ).
    TRY.
        mo_sftp->receive( '00000009690000000200000000' ).
        cl_abap_unit_assert=>fail( 'unknown response id accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD unknown_response.
    DATA lv_request TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    mo_sftp->start( ).
    mo_sftp->receive( '000000050200000003' ).
    lv_request = mo_sftp->build_request(
      iv_type = '03'
      iv_body = 'AA' ).
    TRY.
        mo_sftp->receive( '000000056A00000001' ).
        cl_abap_unit_assert=>fail( 'unknown response type accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD version_six.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    mo_sftp->start( ).
    TRY.
        mo_sftp->receive( '000000050200000006' ).
        cl_abap_unit_assert=>fail( 'SFTP version 6 accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
    cl_abap_unit_assert=>assert_initial( mo_sftp->get_version( ) ).
  ENDMETHOD.


  METHOD truncated_extension.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    mo_sftp->start( ).
    TRY.
* Complete outer packet, but the extension name claims four bytes and has two.
        mo_sftp->receive( '0000000B0200000003000000046162' ).
        cl_abap_unit_assert=>fail( 'truncated VERSION extension accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-malformed_packet ).
    ENDTRY.
    cl_abap_unit_assert=>assert_initial( mo_sftp->get_version( ) ).
  ENDMETHOD.
ENDCLASS.
