CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS rfc4231_tc1 FOR TESTING RAISING cx_static_check.
    METHODS rfc4231_tc2 FOR TESTING RAISING cx_static_check.
    METHODS rfc4231_tc3 FOR TESTING RAISING cx_static_check.
    METHODS rfc4231_tc4 FOR TESTING RAISING cx_static_check.
    METHODS rfc4231_tc6 FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD rfc4231_tc1.
* key = 0x0b x 20, data = "Hi There"
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_hmac=>sha256(
        iv_key  = '0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B'
        iv_data = zcl_oassh_ascii=>to_xstring( 'Hi There' ) )
      exp = 'B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7' ).
  ENDMETHOD.

  METHOD rfc4231_tc2.
* key = "Jefe", data = "what do ya want for nothing?"
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_hmac=>sha256(
        iv_key  = zcl_oassh_ascii=>to_xstring( 'Jefe' )
        iv_data = zcl_oassh_ascii=>to_xstring( 'what do ya want for nothing?' ) )
      exp = '5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843' ).
  ENDMETHOD.

  METHOD rfc4231_tc3.
* key = 0xaa x 20, data = 0xdd x 50
    DATA lv_data TYPE xstring.
    DATA lv_dd   TYPE x LENGTH 1 VALUE 'DD'.

    DO 50 TIMES.
      CONCATENATE lv_data lv_dd INTO lv_data IN BYTE MODE.
    ENDDO.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_hmac=>sha256(
        iv_key  = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        iv_data = lv_data )
      exp = '773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE' ).
  ENDMETHOD.

  METHOD rfc4231_tc4.
* key = 0x01..0x19 (25 bytes), data = 0xcd x 50
    DATA lv_data TYPE xstring.
    DATA lv_cd   TYPE x LENGTH 1 VALUE 'CD'.

    DO 50 TIMES.
      CONCATENATE lv_data lv_cd INTO lv_data IN BYTE MODE.
    ENDDO.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_hmac=>sha256(
        iv_key  = '0102030405060708090A0B0C0D0E0F10111213141516171819'
        iv_data = lv_data )
      exp = '82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B' ).
  ENDMETHOD.

  METHOD rfc4231_tc6.
* key = 0xaa x 131 (longer than the block, is hashed first)
    DATA lv_key TYPE xstring.
    DATA lv_aa  TYPE x LENGTH 1 VALUE 'AA'.

    DO 131 TIMES.
      CONCATENATE lv_key lv_aa INTO lv_key IN BYTE MODE.
    ENDDO.

    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_hmac=>sha256(
        iv_key  = lv_key
        iv_data = zcl_oassh_ascii=>to_xstring( 'Test Using Larger Than Block-Size Key - Hash Key First' ) )
      exp = '60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54' ).
  ENDMETHOD.

ENDCLASS.
