CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    CONSTANTS c_key_1 TYPE xstring VALUE
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'.
    CONSTANTS c_key_2 TYPE xstring VALUE
      '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F'.
    CONSTANTS c_plain TYPE xstring VALUE '0000000C0A14AAAAAAAAAAAAAAAAAAAA'.
    CONSTANTS c_wire TYPE xstring VALUE
      'A39AFCA62252BFE9E42980F4C6C7115A409C60FF0D56B04EB1208FD8EE52AD8E'.
    METHODS openssh_vector FOR TESTING RAISING cx_static_check.
    METHODS tampered_tag FOR TESTING RAISING cx_static_check.
    METHODS malformed_header FOR TESTING RAISING cx_static_check.
    METHODS key RETURNING VALUE(rv_key) TYPE xstring.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD key.
    CONCATENATE c_key_1 c_key_2 INTO rv_key IN BYTE MODE.
  ENDMETHOD.


  METHOD openssh_vector.
    DATA lo_cipher TYPE REF TO zcl_oassh_chachapoly.
    DATA lv_wire TYPE xstring.
    DATA lv_header TYPE xstring.
    DATA lv_ciphertext TYPE xstring.
    DATA lv_tag TYPE xstring.
    lo_cipher = NEW #( key( ) ).
    lv_wire = lo_cipher->encode(
      iv_sequence = 7
      iv_plain    = c_plain ).
    lv_header = lv_wire(4).
    lv_ciphertext = lv_wire(16).
    lv_tag = lv_wire+16(16).
    cl_abap_unit_assert=>assert_equals(
      act = lv_wire
      exp = c_wire ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_cipher->decode_length(
        iv_sequence = 7
        iv_header   = lv_header )
      exp = 12 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_cipher->decode(
        iv_sequence   = 7
        iv_ciphertext = lv_ciphertext
        iv_tag        = lv_tag )
      exp = c_plain ).
  ENDMETHOD.


  METHOD tampered_tag.
    DATA lo_cipher TYPE REF TO zcl_oassh_chachapoly.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    DATA lv_ciphertext TYPE xstring.
    lo_cipher = NEW #( key( ) ).
    lv_ciphertext = c_wire(16).
    TRY.
        lo_cipher->decode(
          iv_sequence   = 7
          iv_ciphertext = lv_ciphertext
          iv_tag        = '00000000000000000000000000000000' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '004' ).
  ENDMETHOD.


  METHOD malformed_header.
    DATA lo_cipher TYPE REF TO zcl_oassh_chachapoly.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    DATA lv_header TYPE xstring.
    lo_cipher = NEW #( key( ) ).
    lv_header = c_wire(5).
    TRY.
        lo_cipher->decode_length(
          iv_sequence = 7
          iv_header   = lv_header ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
  ENDMETHOD.
ENDCLASS.
