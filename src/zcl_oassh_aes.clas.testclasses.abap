CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

* Official AES known-answer vectors: FIPS 197 appendix B/C.

  PRIVATE SECTION.
    METHODS fips197_c1_aes128 FOR TESTING RAISING cx_static_check.
    METHODS fips197_c2_aes192 FOR TESTING RAISING cx_static_check.
    METHODS fips197_c3_aes256 FOR TESTING RAISING cx_static_check.
    METHODS fips197_b_example FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD fips197_c1_aes128.
* FIPS 197 appendix C.1
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_aes=>encrypt_block(
        iv_key   = '000102030405060708090A0B0C0D0E0F'
        iv_block = '00112233445566778899AABBCCDDEEFF' )
      exp = '69C4E0D86A7B0430D8CDB78070B4C55A' ).
  ENDMETHOD.

  METHOD fips197_c2_aes192.
* FIPS 197 appendix C.2
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_aes=>encrypt_block(
        iv_key   = '000102030405060708090A0B0C0D0E0F1011121314151617'
        iv_block = '00112233445566778899AABBCCDDEEFF' )
      exp = 'DDA97CA4864CDFE06EAF70A0EC0D7191' ).
  ENDMETHOD.

  METHOD fips197_c3_aes256.
* FIPS 197 appendix C.3
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_aes=>encrypt_block(
        iv_key   = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
        iv_block = '00112233445566778899AABBCCDDEEFF' )
      exp = '8EA2B7CA516745BFEAFC49904B496089' ).
  ENDMETHOD.

  METHOD fips197_b_example.
* FIPS 197 appendix B worked example (AES-128)
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_aes=>encrypt_block(
        iv_key   = '2B7E151628AED2A6ABF7158809CF4F3C'
        iv_block = '3243F6A8885A308D313198A2E0370734' )
      exp = '3925841D02DC09FBDC118597196A0B32' ).
  ENDMETHOD.

ENDCLASS.
