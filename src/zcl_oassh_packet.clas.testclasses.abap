CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS plain_framing FOR TESTING RAISING cx_static_check.
    METHODS encrypted_roundtrip FOR TESTING RAISING cx_static_check.
    METHODS sequence_numbers FOR TESTING RAISING cx_static_check.
    METHODS initial_sequence FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD plain_framing.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.
    lo_random = NEW #( iv_pattern = 'AA' ).
    lo_packet = NEW #( ii_random = lo_random ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_packet->encode( '14' )
      exp = '0000000C0A14AAAAAAAAAAAAAAAAAAAA' ).
  ENDMETHOD.


  METHOD encrypted_roundtrip.
    CONSTANTS lc_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS lc_iv TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS lc_mac TYPE xstring VALUE '0102030405060708090A0B0C0D0E0F10'.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA lv_wire TYPE xstring.

    lo_random = NEW #( iv_pattern = 'ABCD' ).
    lo_sender = NEW #(
      ii_random      = lo_random
      iv_encrypt_key = lc_key
      iv_encrypt_iv  = lc_iv
      iv_encrypt_mac = lc_mac ).
    lo_receiver = NEW #(
      ii_random      = lo_random
      iv_decrypt_key = lc_key
      iv_decrypt_iv  = lc_iv
      iv_decrypt_mac = lc_mac ).
    lv_wire = lo_sender->encode( '140102030405' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_wire )
      exp = '140102030405' ).
  ENDMETHOD.


  METHOD sequence_numbers.
    CONSTANTS lc_mac TYPE xstring VALUE '00112233445566778899AABBCCDDEEFF'.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA lv_first TYPE xstring.
    DATA lv_second TYPE xstring.

    lo_random = NEW #( iv_pattern = '00' ).
    lo_sender = NEW #(
      ii_random      = lo_random
      iv_encrypt_mac = lc_mac ).
    lo_receiver = NEW #(
      ii_random      = lo_random
      iv_decrypt_mac = lc_mac ).
    lv_first = lo_sender->encode( '01' ).
    lv_second = lo_sender->encode( '01' ).
    cl_abap_unit_assert=>assert_differs(
      act = lv_first
      exp = lv_second ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_first )
      exp = '01' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_second )
      exp = '01' ).
  ENDMETHOD.


  METHOD initial_sequence.
    CONSTANTS lc_mac TYPE xstring VALUE '00112233445566778899AABBCCDDEEFF'.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_default TYPE REF TO zcl_oassh_packet.
    DATA lo_continued TYPE REF TO zcl_oassh_packet.
    lo_random = NEW #( iv_pattern = '00' ).
    lo_default = NEW #(
      ii_random      = lo_random
      iv_encrypt_mac = lc_mac ).
    lo_continued = NEW #(
      ii_random        = lo_random
      iv_encrypt_mac   = lc_mac
      iv_send_sequence = 3 ).
    cl_abap_unit_assert=>assert_differs(
      act = lo_default->encode( '15' )
      exp = lo_continued->encode( '15' ) ).
  ENDMETHOD.
ENDCLASS.
