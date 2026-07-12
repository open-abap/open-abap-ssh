CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS plain_framing FOR TESTING RAISING cx_static_check.
    METHODS encrypted_roundtrip FOR TESTING RAISING cx_static_check.
    METHODS encrypted_streaming FOR TESTING RAISING cx_static_check.
    METHODS chachapoly_roundtrip FOR TESTING RAISING cx_static_check.
    METHODS chachapoly_streaming FOR TESTING RAISING cx_static_check.
    METHODS sequence_numbers FOR TESTING RAISING cx_static_check.
    METHODS initial_sequence FOR TESTING RAISING cx_static_check.
    METHODS rekey_keeps_sequence FOR TESTING RAISING cx_static_check.
    METHODS strict_resets_sequence FOR TESTING RAISING cx_static_check.
    METHODS malformed_fixtures FOR TESTING RAISING cx_static_check.
    METHODS oversize_fixtures FOR TESTING RAISING cx_static_check.
    METHODS assert_rejected
      IMPORTING
        iv_packet         TYPE xstring
        iv_expected_reason TYPE i.
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


  METHOD encrypted_streaming.
* frame a packet the way zcl_oassh does on receive: decrypt the first block to
* learn the length, then hand the rest plus the MAC to decode_remainder
    CONSTANTS lc_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS lc_iv TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS lc_mac TYPE xstring VALUE '0102030405060708090A0B0C0D0E0F10'.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA lv_wire TYPE xstring.
    DATA lv_packet_length TYPE i.
    DATA lv_rest_length TYPE i.
    DATA lv_first_block TYPE xstring.
    DATA lv_rest TYPE xstring.
    DATA lv_mac TYPE xstring.
    DATA lv_mac_offset TYPE i.

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
    lv_wire = lo_sender->encode( '32000000047465737400' ).

    lv_first_block = lv_wire(16).
    lv_packet_length = lo_receiver->decode_length( lv_first_block ).
    lv_rest_length = lv_packet_length + 4 - 16.
    lv_rest = lv_wire+16(lv_rest_length).
    lv_mac_offset = lv_packet_length + 4.
    lv_mac = lv_wire+lv_mac_offset(32).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode_remainder(
        iv_rest = lv_rest
        iv_mac  = lv_mac )
      exp = '32000000047465737400' ).
  ENDMETHOD.


  METHOD chachapoly_roundtrip.
    CONSTANTS:
      lc_key_1 TYPE xstring VALUE '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      lc_key_2 TYPE xstring VALUE '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F'.
    DATA lv_key TYPE xstring.
    DATA lv_wire TYPE xstring.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    CONCATENATE lc_key_1 lc_key_2 INTO lv_key IN BYTE MODE.
    lo_sender = NEW #(
      ii_random            = NEW zcl_oassh_random_fixed( iv_pattern = 'AA' )
      iv_encrypt_key       = lv_key
      iv_encrypt_algorithm = zcl_oassh_packet=>c_cipher_chachapoly
      iv_send_sequence     = 7 ).
    lo_receiver = NEW #(
      ii_random            = NEW zcl_oassh_random_fixed( iv_pattern = 'AA' )
      iv_decrypt_key       = lv_key
      iv_decrypt_algorithm = zcl_oassh_packet=>c_cipher_chachapoly
      iv_receive_sequence  = 7 ).
    lv_wire = lo_sender->encode( '14' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_wire )
      exp = '14' ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lv_wire )
      exp = 28 ).
  ENDMETHOD.


  METHOD chachapoly_streaming.
    CONSTANTS:
      lc_key_1 TYPE xstring VALUE '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      lc_key_2 TYPE xstring VALUE '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F'.
    DATA lv_key TYPE xstring.
    DATA lv_wire TYPE xstring.
    DATA lv_packet_length TYPE i.
    DATA lv_rest_length TYPE i.
    DATA lv_mac_offset TYPE i.
    DATA lv_header TYPE xstring.
    DATA lv_rest TYPE xstring.
    DATA lv_mac TYPE xstring.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    CONCATENATE lc_key_1 lc_key_2 INTO lv_key IN BYTE MODE.
    lo_sender = NEW #(
      ii_random            = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' )
      iv_encrypt_key       = lv_key
      iv_encrypt_algorithm = zcl_oassh_packet=>c_cipher_chachapoly ).
    lo_receiver = NEW #(
      ii_random            = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' )
      iv_decrypt_key       = lv_key
      iv_decrypt_algorithm = zcl_oassh_packet=>c_cipher_chachapoly ).
    lv_wire = lo_sender->encode( '32000000047465737400' ).
    lv_header = lv_wire(4).
    lv_packet_length = lo_receiver->decode_length( lv_header ).
    lv_rest_length = lv_packet_length.
    lv_mac_offset = lv_packet_length + 4.
    lv_rest = lv_wire+4(lv_rest_length).
    lv_mac = lv_wire+lv_mac_offset(16).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode_remainder(
        iv_rest = lv_rest
        iv_mac  = lv_mac )
      exp = '32000000047465737400' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->get_auth_length( )
      exp = 16 ).
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


  METHOD rekey_keeps_sequence.
    CONSTANTS lc_old_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS lc_old_iv TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS lc_old_mac TYPE xstring VALUE '00112233445566778899AABBCCDDEEFF'.
    CONSTANTS lc_new_key TYPE xstring VALUE '000102030405060708090A0B0C0D0E0F'.
    CONSTANTS lc_new_iv TYPE xstring VALUE '101112131415161718191A1B1C1D1E1F'.
    CONSTANTS lc_new_mac TYPE xstring VALUE 'FFEEDDCCBBAA99887766554433221100'.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA lo_expected TYPE REF TO zcl_oassh_packet.
    DATA lv_wire TYPE xstring.

    lo_sender = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_encrypt_key = lc_old_key
      iv_encrypt_iv  = lc_old_iv
      iv_encrypt_mac = lc_old_mac ).
    lo_receiver = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_decrypt_key = lc_old_key
      iv_decrypt_iv  = lc_old_iv
      iv_decrypt_mac = lc_old_mac ).
* advance the original key epoch to sequence number one
    lv_wire = lo_sender->encode( '01' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_wire )
      exp = '01' ).
    lo_sender->rekey_encrypt(
      iv_encrypt_key = lc_new_key
      iv_encrypt_iv  = lc_new_iv
      iv_encrypt_mac = lc_new_mac ).
    lo_receiver->rekey_decrypt(
      iv_decrypt_key = lc_new_key
      iv_decrypt_iv  = lc_new_iv
      iv_decrypt_mac = lc_new_mac ).

    lo_expected = NEW #(
      ii_random        = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_encrypt_key   = lc_new_key
      iv_encrypt_iv    = lc_new_iv
      iv_encrypt_mac   = lc_new_mac
      iv_send_sequence = 1 ).
    lv_wire = lo_sender->encode( '02' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_wire
      exp = lo_expected->encode( '02' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_wire )
      exp = '02' ).
  ENDMETHOD.


  METHOD strict_resets_sequence.
    CONSTANTS lc_old_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS lc_old_iv TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS lc_old_mac TYPE xstring VALUE '00112233445566778899AABBCCDDEEFF'.
    CONSTANTS lc_new_key TYPE xstring VALUE '000102030405060708090A0B0C0D0E0F'.
    CONSTANTS lc_new_iv TYPE xstring VALUE '101112131415161718191A1B1C1D1E1F'.
    CONSTANTS lc_new_mac TYPE xstring VALUE 'FFEEDDCCBBAA99887766554433221100'.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA lo_expected TYPE REF TO zcl_oassh_packet.
    DATA lv_wire TYPE xstring.

    lo_sender = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_encrypt_key = lc_old_key
      iv_encrypt_iv  = lc_old_iv
      iv_encrypt_mac = lc_old_mac ).
    lo_receiver = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_decrypt_key = lc_old_key
      iv_decrypt_iv  = lc_old_iv
      iv_decrypt_mac = lc_old_mac ).
    lv_wire = lo_sender->encode( '01' ).
    lo_receiver->decode( lv_wire ).

    lo_sender->rekey_encrypt(
      iv_encrypt_key = lc_new_key
      iv_encrypt_iv  = lc_new_iv
      iv_encrypt_mac = lc_new_mac ).
    lo_receiver->rekey_decrypt(
      iv_decrypt_key = lc_new_key
      iv_decrypt_iv  = lc_new_iv
      iv_decrypt_mac = lc_new_mac ).
    lo_sender->reset_send_sequence( ).
    lo_receiver->reset_receive_sequence( ).

    lo_expected = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_encrypt_key = lc_new_key
      iv_encrypt_iv  = lc_new_iv
      iv_encrypt_mac = lc_new_mac ).
    lv_wire = lo_sender->encode( '02' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_wire
      exp = lo_expected->encode( '02' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->decode( lv_wire )
      exp = '02' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_sender->get_send_sequence( )
      exp = 1 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_receiver->get_receive_sequence( )
      exp = 1 ).
  ENDMETHOD.


  METHOD assert_rejected.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_packet = NEW #( ii_random = NEW zcl_oassh_random_fixed( ) ).
    TRY.
        lo_packet->decode( iv_packet ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = iv_expected_reason ).
  ENDMETHOD.


  METHOD malformed_fixtures.
* Deterministic parser corpus: truncated, non-aligned, length mismatch,
* insufficient padding, and padding that consumes the full packet.
    assert_rejected(
      iv_packet          = '00000000'
      iv_expected_reason = zcx_oassh_error=>c_reason-malformed_packet ).
    assert_rejected(
      iv_packet          = '0000000C0A00000000000000'
      iv_expected_reason = zcx_oassh_error=>c_reason-malformed_packet ).
    assert_rejected(
      iv_packet          = '0000000D0A1400000000000000000000'
      iv_expected_reason = zcx_oassh_error=>c_reason-malformed_packet ).
    assert_rejected(
      iv_packet          = '0000000C030102030405060708000000'
      iv_expected_reason = zcx_oassh_error=>c_reason-malformed_packet ).
    assert_rejected(
      iv_packet          = '0000000C0C0000000000000000000000'
      iv_expected_reason = zcx_oassh_error=>c_reason-malformed_packet ).
  ENDMETHOD.


  METHOD oversize_fixtures.
    CONSTANTS lc_mac TYPE xstring VALUE '00112233445566778899AABBCCDDEEFF'.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.
    DATA lo_sender TYPE REF TO zcl_oassh_packet.
    DATA lo_receiver TYPE REF TO zcl_oassh_packet.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    DATA lv_wire TYPE xstring.
    DATA lv_bad_mac TYPE xstring.
    lo_packet = NEW #( ii_random = NEW zcl_oassh_random_fixed( ) ).
    li_random = NEW zcl_oassh_random_fixed( ).
    TRY.
        lo_packet->encode( li_random->bytes( 32769 ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-packet_too_large ).

    CLEAR lv_reason.
    TRY.
        lo_packet->decode_length( '00010000000000000000000000000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-packet_too_large ).

    CLEAR lv_reason.
    TRY.
        lo_packet->decode_length( '7FFFFFFF000000000000000000000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-packet_too_large ).

    lo_sender = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_encrypt_mac = lc_mac ).
    lo_receiver = NEW #(
      ii_random      = NEW zcl_oassh_random_fixed( iv_pattern = '00' )
      iv_decrypt_mac = lc_mac ).
    lv_wire = lo_sender->encode( '01' ).
    lv_bad_mac = lv_wire(16) &&
      '0000000000000000000000000000000000000000000000000000000000000000'.
    CLEAR lv_reason.
    TRY.
        lo_receiver->decode( lv_bad_mac ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-mac_invalid ).
  ENDMETHOD.
ENDCLASS.
