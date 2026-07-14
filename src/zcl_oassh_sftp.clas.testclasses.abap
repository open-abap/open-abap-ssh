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
    METHODS download_empty_data FOR TESTING RAISING cx_static_check.
    METHODS download_full_chunk FOR TESTING RAISING cx_static_check.
    METHODS download_eof FOR TESTING RAISING cx_static_check.
    METHODS download_open_error FOR TESTING RAISING cx_static_check.
    METHODS download_read_error_closes FOR TESTING RAISING cx_static_check.
    METHODS download_stale_id FOR TESTING RAISING cx_static_check.
    METHODS upload_short FOR TESTING RAISING cx_static_check.
    METHODS upload_multiple_chunks FOR TESTING RAISING cx_static_check.
    METHODS upload_empty FOR TESTING RAISING cx_static_check.
    METHODS upload_write_error_closes FOR TESTING RAISING cx_static_check.
    METHODS stat_attrs FOR TESTING RAISING cx_static_check.
    METHODS lstat_wire FOR TESTING RAISING cx_static_check.
    METHODS stat_extensions FOR TESTING RAISING cx_static_check.
    METHODS stat_status FOR TESTING RAISING cx_static_check.
    METHODS stat_malformed_attrs FOR TESTING RAISING cx_static_check.
    METHODS list_directory FOR TESTING RAISING cx_static_check.
    METHODS list_read_error_closes FOR TESTING RAISING cx_static_check.
    METHODS list_open_error FOR TESTING RAISING cx_static_check.
    METHODS list_invalid_count FOR TESTING RAISING cx_static_check.
    METHODS mutation_wire FOR TESTING RAISING cx_static_check.
    METHODS mutation_status_error FOR TESTING RAISING cx_static_check.
    METHODS mutation_wrong_response FOR TESTING RAISING cx_static_check.
    METHODS realpath_name FOR TESTING RAISING cx_static_check.
    METHODS realpath_invalid_count FOR TESTING RAISING cx_static_check.
    METHODS realpath_status FOR TESTING RAISING cx_static_check.
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
* Short DATA advances by its actual length; only explicit EOF ends the read loop.
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
      exp = '0000001605000000030000000148000000000000000300008000' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_data( )
      exp = '616263' ).
    lv_out = mo_sftp->receive( '000000116500000003000000010000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000040000000148' ).
    lv_out = mo_sftp->receive( '000000116500000004000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = -1 ).
  ENDMETHOD.


  METHOD download_empty_data.
* A zero-length DATA response makes no offset progress and would otherwise loop.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_download( 'a' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    TRY.
        mo_sftp->receive( '00000009670000000200000000' ).
        cl_abap_unit_assert=>fail( 'zero-length DATA accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
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
    DATA lv_prefix TYPE xstring.
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
    lv_prefix = lv_out(26).
    cl_abap_unit_assert=>assert_equals(
      act = lv_prefix
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


  METHOD stat_attrs.
* Sections 5 and 6.8: flags determine the exact order of every ATTRS field.
    DATA lv_out TYPE xstring.
    DATA ls_attrs TYPE zcl_oassh_sftp=>ty_attrs.
    lv_out = mo_sftp->start_stat( 'a' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A11000000010000000161' ).
    lv_out = mo_sftp->receive(
      '0000002569000000010000000F00000000000000030000000100000002000081A40000000400000005' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    ls_attrs = mo_sftp->get_attrs( ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-flags
      exp = '0000000F' ).
    cl_abap_unit_assert=>assert_true( ls_attrs-has_size ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-size
      exp = '0000000000000003' ).
    cl_abap_unit_assert=>assert_true( ls_attrs-has_uid_gid ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-uid
      exp = '00000001' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-gid
      exp = '00000002' ).
    cl_abap_unit_assert=>assert_true( ls_attrs-has_permissions ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-permissions
      exp = '000081A4' ).
    cl_abap_unit_assert=>assert_true( ls_attrs-has_acmodtime ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-atime
      exp = '00000004' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-mtime
      exp = '00000005' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
  ENDMETHOD.


  METHOD lstat_wire.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_stat(
      iv_path  = 'a'
      iv_lstat = abap_true ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A07000000010000000161' ).
  ENDMETHOD.


  METHOD stat_extensions.
* Unknown extension values are preserved as opaque byte strings.
    DATA lv_out TYPE xstring.
    DATA ls_attrs TYPE zcl_oassh_sftp=>ty_attrs.
    lv_out = mo_sftp->start_stat( 'a' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000002169000000018000000000000002000000016100000000000000016200000002CCCC' ).
    ls_attrs = mo_sftp->get_attrs( ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( ls_attrs-extensions )
      exp = 2 ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-extensions[ 1 ]-extension_type
      exp = '61' ).
    cl_abap_unit_assert=>assert_initial( ls_attrs-extensions[ 1 ]-extension_data ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_attrs-extensions[ 2 ]-extension_data
      exp = 'CCCC' ).
  ENDMETHOD.


  METHOD stat_status.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_stat( 'missing' ).
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


  METHOD stat_malformed_attrs.
* Unsupported v3 flag bits and truncated flagged fields are rejected.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_stat( 'a' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '00000009690000000100000010' ).
        cl_abap_unit_assert=>fail( 'unsupported ATTRS flag accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_stat( 'a' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '0000000D69000000010000000100000000' ).
        cl_abap_unit_assert=>fail( 'truncated ATTRS size accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-malformed_packet ).
    ENDTRY.
  ENDMETHOD.


  METHOD list_directory.
* OPENDIR -> HANDLE -> repeated READDIR/NAME -> EOF -> CLOSE/OK.
    DATA lv_out TYPE xstring.
    DATA lt_names TYPE zcl_oassh_sftp=>ty_names.
    lv_out = mo_sftp->start_list( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A0B000000010000000164' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A0C000000020000000148' ).
    lv_out = mo_sftp->receive(
      '0000002D680000000200000002000000016100000001410000000100000000000000030000000162000000014200000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A0C000000030000000148' ).
    lt_names = mo_sftp->get_names( ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( lt_names )
      exp = 2 ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_names[ 1 ]-filename
      exp = '61' ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_names[ 1 ]-longname
      exp = '41' ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_names[ 1 ]-attrs-size
      exp = '0000000000000003' ).
    lv_out = mo_sftp->receive( '000000116500000003000000010000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A04000000040000000148' ).
    lv_out = mo_sftp->receive( '000000116500000004000000000000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).
  ENDMETHOD.


  METHOD list_read_error_closes.
* A non-EOF READDIR error is retained, but the directory handle is closed.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_list( 'd' ).
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
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 3 ).
  ENDMETHOD.


  METHOD list_open_error.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_list( 'missing' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '000000116500000001000000020000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 2 ).
    cl_abap_unit_assert=>assert_initial( mo_sftp->mv_handle ).
  ENDMETHOD.


  METHOD list_invalid_count.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_list( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    TRY.
        mo_sftp->receive( '00000009680000000200000000' ).
        cl_abap_unit_assert=>fail( 'empty NAME batch accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_list( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '0000000A66000000010000000148' ).
    TRY.
        mo_sftp->receive( '00000009680000000200001001' ).
        cl_abap_unit_assert=>fail( 'oversized NAME count accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD mutation_wire.
* v3 REMOVE/MKDIR/RMDIR/RENAME have exact path encodings and require STATUS OK.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_mkdir( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000E0E00000001000000016400000000' ).
    lv_out = mo_sftp->receive( '000000116500000001000000000000000000000000' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_state( )
      exp = zcl_oassh_sftp=>c_state-finished ).

    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_rmdir( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A0F000000010000000164' ).

    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_remove( 'f' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A0D000000010000000166' ).

    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_rename(
      iv_old_path = 'a'
      iv_new_path = 'b' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000F120000000100000001610000000162' ).
  ENDMETHOD.


  METHOD mutation_status_error.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_remove( 'missing' ).
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


  METHOD mutation_wrong_response.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_mkdir( 'd' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '00000009690000000100000000' ).
        cl_abap_unit_assert=>fail( 'non-STATUS mutation reply accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD realpath_name.
    DATA lv_out TYPE xstring.
    DATA ls_name TYPE zcl_oassh_sftp=>ty_name.
    lv_out = mo_sftp->start_realpath( '.' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_out
      exp = '0000000A1000000001000000012E' ).
    lv_out = mo_sftp->receive( '00000020680000000100000001000000022F640000000144000000010000000000000003' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    ls_name = mo_sftp->get_realpath( ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_name-filename
      exp = '2F64' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_name-longname
      exp = '44' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_name-attrs-size
      exp = '0000000000000003' ).
  ENDMETHOD.


  METHOD realpath_invalid_count.
    DATA lv_out TYPE xstring.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lv_out = mo_sftp->start_realpath( '.' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '00000009680000000100000000' ).
        cl_abap_unit_assert=>fail( 'empty REALPATH NAME accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_realpath( '.' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '00000009680000000100000002' ).
        cl_abap_unit_assert=>fail( 'multiple REALPATH names accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
    mo_sftp = NEW #( ).
    lv_out = mo_sftp->start_realpath( '.' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    TRY.
        mo_sftp->receive( '00000015680000000100000001000000000000000000000000' ).
        cl_abap_unit_assert=>fail( 'empty canonical path accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->get_reason( )
          exp = zcx_oassh_error=>c_reason-sftp_protocol ).
    ENDTRY.
  ENDMETHOD.


  METHOD realpath_status.
    DATA lv_out TYPE xstring.
    lv_out = mo_sftp->start_realpath( 'missing' ).
    lv_out = mo_sftp->receive( '000000050200000003' ).
    lv_out = mo_sftp->receive( '000000116500000001000000020000000000000000' ).
    cl_abap_unit_assert=>assert_initial( lv_out ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_sftp->get_error_status( )
      exp = 2 ).
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
