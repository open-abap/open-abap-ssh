CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    CONSTANTS c_sig1_a TYPE xstring VALUE
      'E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155'.
    CONSTANTS c_sig1_b TYPE xstring VALUE
      '5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B'.
    CONSTANTS c_sig2_a TYPE xstring VALUE
      '92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA'.
    CONSTANTS c_sig2_b TYPE xstring VALUE
      '085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00'.
    METHODS rfc8032_empty FOR TESTING.
    METHODS rfc8032_one_byte FOR TESTING.
    METHODS rejects_modified FOR TESTING.
    METHODS rejects_small_order FOR TESTING.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD rfc8032_empty.
    DATA lv_empty TYPE xstring.
    DATA lv_signature TYPE xstring.
    CONCATENATE c_sig1_a c_sig1_b INTO lv_signature IN BYTE MODE.
    cl_abap_unit_assert=>assert_true(
      zcl_oassh_ed25519=>verify(
        iv_public_key = 'D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A'
        iv_message    = lv_empty
        iv_signature  = lv_signature ) ).
  ENDMETHOD.


  METHOD rfc8032_one_byte.
    DATA lv_signature TYPE xstring.
    CONCATENATE c_sig2_a c_sig2_b INTO lv_signature IN BYTE MODE.
    cl_abap_unit_assert=>assert_true(
      zcl_oassh_ed25519=>verify(
        iv_public_key = '3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C'
        iv_message    = '72'
        iv_signature  = lv_signature ) ).
  ENDMETHOD.


  METHOD rejects_modified.
    DATA lv_empty TYPE xstring.
    DATA lv_bad_a TYPE xstring VALUE
      'E4564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155'.
    DATA lv_signature TYPE xstring.
    CONCATENATE lv_bad_a c_sig1_b INTO lv_signature IN BYTE MODE.
    cl_abap_unit_assert=>assert_false(
      zcl_oassh_ed25519=>verify(
        iv_public_key = 'D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A'
        iv_message    = lv_empty
        iv_signature  = lv_signature ) ).
  ENDMETHOD.


  METHOD rejects_small_order.
* Identity public key and R=B, S=1 satisfy the raw group equation for every
* message unless small-order public keys are rejected explicitly.
    DATA lv_public TYPE xstring VALUE
      '0100000000000000000000000000000000000000000000000000000000000000'.
    DATA lv_r TYPE xstring VALUE
      '5866666666666666666666666666666666666666666666666666666666666666'.
    DATA lv_s TYPE xstring VALUE
      '0100000000000000000000000000000000000000000000000000000000000000'.
    DATA lv_signature TYPE xstring.
    DATA lv_empty TYPE xstring.
    CONCATENATE lv_r lv_s INTO lv_signature IN BYTE MODE.
    cl_abap_unit_assert=>assert_false(
      zcl_oassh_ed25519=>verify(
        iv_public_key = lv_public
        iv_message    = lv_empty
        iv_signature  = lv_signature ) ).
  ENDMETHOD.
ENDCLASS.
