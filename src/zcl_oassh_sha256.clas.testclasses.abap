CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS empty FOR TESTING RAISING cx_static_check.
    METHODS abc FOR TESTING RAISING cx_static_check.
    METHODS two_blocks FOR TESTING RAISING cx_static_check.
    METHODS exactly_one_block FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD empty.
* NIST: SHA-256 of the empty message
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_sha256=>hash( '' )
      exp = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' ).
  ENDMETHOD.

  METHOD abc.
* NIST FIPS 180-4 example: "abc"
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_sha256=>hash( zcl_oassh_ascii=>to_xstring( 'abc' ) )
      exp = 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD' ).
  ENDMETHOD.

  METHOD two_blocks.
* NIST FIPS 180-4 example: 448-bit message, spans two blocks
    DATA lv_text TYPE string.
    lv_text = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_sha256=>hash( zcl_oassh_ascii=>to_xstring( lv_text ) )
      exp = '248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1' ).
  ENDMETHOD.

  METHOD exactly_one_block.
* 56 bytes of 'a' forces padding into a second block (length field needs 8 bytes)
    DATA lv_text TYPE string.
    lv_text = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_sha256=>hash( zcl_oassh_ascii=>to_xstring( lv_text ) )
      exp = 'B35439A4AC6F0948B6D6F9E3C6AF0F5F590CE20F1BDE7090EF7970686EC6738A' ).
  ENDMETHOD.

ENDCLASS.
