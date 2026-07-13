CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS own_proposal FOR TESTING RAISING cx_static_check.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS rejects_reserved FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD own_proposal.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA ls_data TYPE zcl_oassh_message_20=>ty_data.
    lo_random = NEW #( iv_pattern = '0102' ).
    ls_data = zcl_oassh_message_20=>create( lo_random ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-cookie
      exp = '01020102010201020102010201020102' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-kex_algorithms[ 1 ]
      exp = 'curve25519-sha256' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-kex_algorithms[ 2 ]
      exp = 'diffie-hellman-group14-sha256' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-server_host_key_algorithms[ 1 ]
      exp = 'rsa-sha2-256' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-server_host_key_algorithms[ 2 ]
      exp = 'ssh-ed25519' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-encryption_algorithms_c_to_s[ 1 ]
      exp = 'aes128-ctr' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-encryption_algorithms_c_to_s[ 2 ]
      exp = 'chacha20-poly1305@openssh.com' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_data-mac_algorithms_s_to_c[ 1 ]
      exp = 'hmac-sha2-256' ).
  ENDMETHOD.


  METHOD roundtrip.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_expected TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_20=>ty_data.
    lo_random = NEW #( iv_pattern = 'AB' ).
    ls_expected = zcl_oassh_message_20=>create( lo_random ).
    lo_stream = zcl_oassh_message_20=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_20=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD rejects_reserved.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_data TYPE zcl_oassh_message_20=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_random = NEW #( iv_pattern = 'AB' ).
    ls_data = zcl_oassh_message_20=>create( lo_random ).
    ls_data-reserved = 1.
    lo_stream = zcl_oassh_message_20=>serialize( ls_data ).
    TRY.
        zcl_oassh_message_20=>parse( lo_stream ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.
ENDCLASS.
