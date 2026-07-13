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
    METHODS download_short FOR TESTING RAISING cx_static_check.
    METHODS download_full_chunk FOR TESTING RAISING cx_static_check.
    METHODS download_eof FOR TESTING RAISING cx_static_check.
    METHODS download_open_error FOR TESTING RAISING cx_static_check.
    METHODS download_read_error_closes FOR TESTING RAISING cx_static_check.
    METHODS download_stale_id FOR TESTING RAISING cx_static_check.
    METHODS upload_short FOR TESTING RAISING cx_static_check.
    METHODS upload_multiple_chunks FOR TESTING RAISING cx_static_check.
    METHODS upload_empty FOR TESTING RAISING cx_static_check.
    METHODS upload_write_error_closes FOR TESTING RAISING cx_static_check.
    METHODS typed_status_error FOR TESTING RAISING cx_static_check.
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


  METHOD download_short.
* INIT -> VERSION -> OPEN -> HANDLE -> short DATA -> CLOSE -> STATUS OK.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_download( 'a' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '000000050100000003' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '00000012030000000100000001610000000100000000' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000001605000000020000000148000000000000000000008000' ).
    lv_out = mo_sftp->receive( '0000000C670000000200000003616263' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000030000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_data( )
      exp = '616263' ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = -1 ).
  ENDMETHOD.


  METHOD download_full_chunk.
* A complete 32768-byte DATA advances the uint64 offset by the actual bytes and
* issues another READ rather than assuming EOF.
    DATA lo_packet TYPE REF TO zcl_oassh_stream.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_chunk TYPE xstring.
    DATA lv_out TYPE xstring.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '5A' ).
    lv_chunk = li_random->bytes( 32768 ).
    lv_out = mo_sftp->start_download( 'large' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    lo_packet = NEW #( ).
    lo_packet->uint32_encode( 32777 ).
    lo_packet->byte_encode( '67' ).
    lo_packet->uint32_encode( 2 ).
    lo_packet->string_encode( lv_chunk ).
    lv_out = mo_sftp->receive( lo_packet->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000001605000000030000000148000000000000800000008000' ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( mo_sftp->get_data( ) )
      exp = 32768 ).
  ENDMETHOD.


  METHOD download_eof.
* An empty file may answer the first READ with SSH_FX_EOF.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_download( 'empty' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    lv_out = mo_sftp->receive( '000000116500000002000000010000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000030000000148' ).
    cl_abap_unit_assert=>assert_initial( mo_sftp->get_data( ) ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
  ENDMETHOD.


  METHOD download_open_error.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_download( 'missing' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '000000116500000001000000020000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 2 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
  ENDMETHOD.


  METHOD download_read_error_closes.
* A failed READ retains its status but still closes the live handle first.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_download( 'denied' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    lv_out = mo_sftp->receive( '000000116500000002000000030000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000030000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 3 ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 3 ).
  ENDMETHOD.


  METHOD download_stale_id.
* Once EOF consumed READ id 2, later DATA for id 2 is never accepted while
* CLOSE id 3 is outstanding.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_download( 'empty' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    lv_out = mo_sftp->receive( '000000116500000002000000010000000000000000' ).
    TRY.
        mo_sftp->receive( '00000009670000000200000000' ).
        cl_abap_unit_assert=>fail( 'response for completed READ accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD upload_short.
* INIT -> VERSION -> OPEN(WRITE|CREAT|TRUNC) -> HANDLE -> WRITE -> CLOSE.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_upload(
      iv_path = 'a'
      iv_data = '010203' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '000000050100000003' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '00000012030000000100000001610000001A00000000' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000001906000000020000000148000000000000000000000003010203' ).
    lv_out = mo_sftp->receive( '000000116500000002000000000000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000030000000148' ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
  ENDMETHOD.


  METHOD upload_multiple_chunks.
* WRITE acknowledgements advance the uint64 offset by exactly the acknowledged
* chunk length; the final byte is sent at offset 32768.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_data TYPE xstring.
    DATA lv_tail TYPE xstring.
    DATA lv_out TYPE xstring.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '5A' ).
    lv_data = li_random->bytes( 32768 ).
    lv_tail = 'BB'.
    CONCATENATE lv_data lv_tail INTO lv_data IN BYTE MODE.
    lv_out = mo_sftp->start_upload(
      iv_path = 'large'
      iv_data = lv_data ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lv_out )
      exp = 32794 ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out(26)
      exp = '0000801606000000020000000148000000000000000000008000' ).
    lv_out = mo_sftp->receive( '000000116500000002000000000000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000001706000000030000000148000000000000800000000001BB' ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000040000000148' ).
  ENDMETHOD.


  METHOD upload_empty.
* Empty uploads still create/truncate the file and close the returned handle.
    DATA lv_out TYPE xstring.
    DATA lv_empty TYPE xstring.
    lv_out = mo_sftp->start_upload(
      iv_path = 'empty'
      iv_data = lv_empty ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000020000000148' ).
  ENDMETHOD.


  METHOD upload_write_error_closes.
* A failed WRITE is reported only after the live handle is closed.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_upload(
      iv_path = 'denied'
      iv_data = 'AA' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    lv_out = mo_sftp->receive( '000000116500000002000000030000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000030000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 3 ).
    lv_out = mo_sftp->receive( '000000116500000003000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 3 ).
  ENDMETHOD.


  METHOD typed_status_error.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    TRY.
        zcx_oassh_error=>raise(
          iv_reason      = zcx_oassh_error=>c_reason-sftp_status
          iv_sftp_status = 2 ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_status ).
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_sftp_status( )
          exp = 2 ).
    ENDTRY.
  ENDMETHOD.
ENDCLASS.
