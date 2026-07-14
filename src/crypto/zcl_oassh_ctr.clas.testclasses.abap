CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    CONSTANTS c_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS c_ctr TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS c_plain_1 TYPE xstring VALUE
      '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51'.
    CONSTANTS c_plain_2 TYPE xstring VALUE
      '30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    CONSTANTS c_cipher_1 TYPE xstring VALUE
      '874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF'.
    CONSTANTS c_cipher_2 TYPE xstring VALUE
      '5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE'.

    METHODS sp800_38a_encrypt FOR TESTING RAISING cx_static_check.
    METHODS decrypt_is_symmetric FOR TESTING RAISING cx_static_check.
    METHODS split_calls_keep_stream FOR TESTING RAISING cx_static_check.
    METHODS large_stream_matches FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD sp800_38a_encrypt.
    DATA lo_ctr TYPE REF TO zcl_oassh_ctr.
    DATA lv_plain TYPE xstring.
    DATA lv_cipher TYPE xstring.
    CONCATENATE c_plain_1 c_plain_2 INTO lv_plain IN BYTE MODE.
    CONCATENATE c_cipher_1 c_cipher_2 INTO lv_cipher IN BYTE MODE.
    lo_ctr = NEW #(
      iv_key     = c_key
      iv_counter = c_ctr ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ctr->crypt( lv_plain )
      exp = lv_cipher ).
  ENDMETHOD.


  METHOD decrypt_is_symmetric.
    DATA lo_ctr TYPE REF TO zcl_oassh_ctr.
    DATA lv_plain TYPE xstring.
    DATA lv_cipher TYPE xstring.
    CONCATENATE c_plain_1 c_plain_2 INTO lv_plain IN BYTE MODE.
    CONCATENATE c_cipher_1 c_cipher_2 INTO lv_cipher IN BYTE MODE.
    lo_ctr = NEW #(
      iv_key     = c_key
      iv_counter = c_ctr ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ctr->crypt( lv_cipher )
      exp = lv_plain ).
  ENDMETHOD.


  METHOD split_calls_keep_stream.
    DATA lo_ctr TYPE REF TO zcl_oassh_ctr.
    DATA lv_actual TYPE xstring.
    DATA lv_part TYPE xstring.
    DATA lv_slice TYPE xstring.
    DATA lv_plain TYPE xstring.
    DATA lv_cipher TYPE xstring.
    CONCATENATE c_plain_1 c_plain_2 INTO lv_plain IN BYTE MODE.
    CONCATENATE c_cipher_1 c_cipher_2 INTO lv_cipher IN BYTE MODE.

    lo_ctr = NEW #(
      iv_key     = c_key
      iv_counter = c_ctr ).
    lv_slice = lv_plain(7).
    lv_actual = lo_ctr->crypt( lv_slice ).
    lv_slice = lv_plain+7(19).
    lv_part = lo_ctr->crypt( lv_slice ).
    CONCATENATE lv_actual lv_part INTO lv_actual IN BYTE MODE.
    lv_slice = lv_plain+26.
    lv_part = lo_ctr->crypt( lv_slice ).
    CONCATENATE lv_actual lv_part INTO lv_actual IN BYTE MODE.

    cl_abap_unit_assert=>assert_equals(
      act = lv_actual
      exp = lv_cipher ).
  ENDMETHOD.


  METHOD large_stream_matches.
    DATA lo_whole TYPE REF TO zcl_oassh_ctr.
    DATA lo_split TYPE REF TO zcl_oassh_ctr.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_plain TYPE xstring.
    DATA lv_expected TYPE xstring.
    DATA lv_actual TYPE xstring.
    DATA lv_part TYPE xstring.
    DATA lv_slice TYPE xstring.
    DATA lv_offset TYPE i.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '0011223344556677' ).
    lv_plain = li_random->bytes( 4096 ).
    lo_whole = NEW #(
      iv_key     = c_key
      iv_counter = c_ctr ).
    lo_split = NEW #(
      iv_key     = c_key
      iv_counter = c_ctr ).
    lv_expected = lo_whole->crypt( lv_plain ).
    DO 64 TIMES.
      lv_offset = ( sy-index - 1 ) * 64.
      lv_slice = lv_plain+lv_offset(64).
      lv_part = lo_split->crypt( lv_slice ).
      CONCATENATE lv_actual lv_part INTO lv_actual IN BYTE MODE.
    ENDDO.
    cl_abap_unit_assert=>assert_equals(
      act = lv_actual
      exp = lv_expected ).
  ENDMETHOD.

ENDCLASS.
