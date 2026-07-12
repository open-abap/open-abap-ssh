CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

* Reference vectors were produced independently with Node.js crypto
* (crypto.createHash('sha256')) implementing the RFC 4253 sections 7.2/8
* constructions on the fixed inputs below, so the tests do not merely
* re-derive the expected value from zcl_oassh_sha256.

  PRIVATE SECTION.
    CONSTANTS:
      c_v_c TYPE xstring VALUE '5353482D322E302D4F70656E414241505F302E31',
      c_v_s TYPE xstring VALUE '5353482D322E302D4F70656E5353485F392E36',
      c_i_c TYPE xstring VALUE '140011223344556677889900AABBCCDDEEFF01',
      c_i_s TYPE xstring VALUE '14FFEEDDCCBBAA99887766554433221100AB',
      c_k_s TYPE xstring VALUE '0000000B7373682D65643235353139AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      c_q_c TYPE xstring VALUE 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      c_q_s TYPE xstring VALUE 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      c_k   TYPE xstring VALUE 'C011111111111111111111111111111111111111111111111111111111111111',
      c_h   TYPE xstring VALUE 'D64476A12B1D36F87157B2A328205BB8071B15CDF3076361F00E80518CA44545'.

    METHODS exchange_hash FOR TESTING RAISING cx_static_check.
    METHODS exchange_hash_dh FOR TESTING RAISING cx_static_check.
    METHODS derive_key_a FOR TESTING RAISING cx_static_check.
    METHODS derive_key_b FOR TESTING RAISING cx_static_check.
    METHODS derive_key_c FOR TESTING RAISING cx_static_check.
    METHODS derive_key_d FOR TESTING RAISING cx_static_check.
    METHODS derive_key_e FOR TESTING RAISING cx_static_check.
    METHODS derive_key_f FOR TESTING RAISING cx_static_check.
    METHODS derive_key_two_blocks FOR TESTING RAISING cx_static_check.
    METHODS derive_key_three_blocks FOR TESTING RAISING cx_static_check.

    METHODS key
      IMPORTING
        iv_letter     TYPE c
        iv_length     TYPE i
      RETURNING
        VALUE(rv_key) TYPE xstring.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD key.
* session id equals the exchange hash for the first (only) kex
    rv_key = zcl_oassh_kdf=>derive_key(
      iv_k          = c_k
      iv_h          = c_h
      iv_letter     = iv_letter
      iv_session_id = c_h
      iv_length     = iv_length ).
  ENDMETHOD.

  METHOD exchange_hash.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_kdf=>exchange_hash(
        iv_v_c = c_v_c
        iv_v_s = c_v_s
        iv_i_c = c_i_c
        iv_i_s = c_i_s
        iv_k_s = c_k_s
        iv_q_c = c_q_c
        iv_q_s = c_q_s
        iv_k   = c_k )
      exp = c_h ).
  ENDMETHOD.


  METHOD exchange_hash_dh.
* Independent Node crypto vector; 0x80 and 0xFF exercise mpint sign padding.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_kdf=>exchange_hash_dh(
        iv_v_c = c_v_c
        iv_v_s = c_v_s
        iv_i_c = c_i_c
        iv_i_s = c_i_s
        iv_k_s = c_k_s
        iv_e   = '80'
        iv_f   = '7F'
        iv_k   = 'FF' )
      exp = '433037EB4C89853CF66ED5C479CAA3134B166DF51171960C3224C3A94F73359D' ).
  ENDMETHOD.

  METHOD derive_key_a.
* initial IV, client to server
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'A' iv_length = 16 )
      exp = 'C43B34A4096EFFDAEDC91EA4581B96FE' ).
  ENDMETHOD.

  METHOD derive_key_b.
* initial IV, server to client
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'B' iv_length = 16 )
      exp = '3BADF517D1EC211A003EE57D6C0F3768' ).
  ENDMETHOD.

  METHOD derive_key_c.
* encryption key, client to server
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'C' iv_length = 16 )
      exp = '0194E20BEA872DBF33F5B36CCEDCC8C4' ).
  ENDMETHOD.

  METHOD derive_key_d.
* encryption key, server to client
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'D' iv_length = 16 )
      exp = 'E272DFCA6D1DBB85928BF5A3FC527AFF' ).
  ENDMETHOD.

  METHOD derive_key_e.
* integrity key, client to server
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'E' iv_length = 32 )
      exp = 'CEDBA033948F01949DC3CF20FE474E6F7238A239BF9EA8A64CFC4E787A4C1E77' ).
  ENDMETHOD.

  METHOD derive_key_f.
* integrity key, server to client
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'F' iv_length = 32 )
      exp = 'B562B7B1D9FADEC9EBF1531F6896F8B79B65A47BD8112EAFD7E716898D0A3A04' ).
  ENDMETHOD.

  METHOD derive_key_two_blocks.
* 64 bytes forces the K1 || K2 extension path
    CONSTANTS:
      lc_1 TYPE xstring VALUE 'C43B34A4096EFFDAEDC91EA4581B96FE8E23542AACE3C4EFBFC604C5996A5609',
      lc_2 TYPE xstring VALUE 'F29883B7A1DBF2C083EEADE9745B7D836D9E4FB56F20CF6019AE8D1373E65989'.
    DATA lv_exp TYPE xstring.
    CONCATENATE lc_1 lc_2 INTO lv_exp IN BYTE MODE.
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'A' iv_length = 64 )
      exp = lv_exp ).
  ENDMETHOD.

  METHOD derive_key_three_blocks.
* 80 bytes forces the K1 || K2 || K3 extension path
    CONSTANTS:
      lc_1 TYPE xstring VALUE '0194E20BEA872DBF33F5B36CCEDCC8C4085953B6D4240DEA4C0C25FA8C01575D',
      lc_2 TYPE xstring VALUE '0A14789A24EB443A18545100D86CB27645EFD14FF5AAAA76CF88556AC159436C',
      lc_3 TYPE xstring VALUE '6D47AD2FEA615440239A7AA48462556D'.
    DATA lv_exp TYPE xstring.
    CONCATENATE lc_1 lc_2 lc_3 INTO lv_exp IN BYTE MODE.
    cl_abap_unit_assert=>assert_equals(
      act = key( iv_letter = 'C' iv_length = 80 )
      exp = lv_exp ).
  ENDMETHOD.

ENDCLASS.
