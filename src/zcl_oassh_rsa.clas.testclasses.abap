CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    CONSTANTS c_message TYPE xstring VALUE
      '6F70656E2D616261702D7373682052534120766572696669636174696F6E20766563746F72'.
    CONSTANTS c_n_1 TYPE xstring VALUE
      'D50D7F630534E2246419F9C6460BF516FE6D1FC0B158D855B57E191EB252059E'.
    CONSTANTS c_n_2 TYPE xstring VALUE
      'EAA8F1F5499697D71A859BA2865E8FE8CEC0B7BB419736AB024B6F8E2C5B73AB'.
    CONSTANTS c_n_3 TYPE xstring VALUE
      '0D4C7E2DE600818E131ED5C3BA9751FBAF3383FA2AEC5CA3678094572714BAFA'.
    CONSTANTS c_n_4 TYPE xstring VALUE
      'D8F307581CDDCD4FCE7BE23E0D705FE9F22A785526BD63C53DEFA2A3C782224D'.
    CONSTANTS c_e TYPE xstring VALUE '010001'.
    CONSTANTS c_signature_1 TYPE xstring VALUE
      '9247E20EE048CC1FC591473A2133CF758F45B721142323E7934EA9C4F5A79540'.
    CONSTANTS c_signature_2 TYPE xstring VALUE
      '82CA94960FB18BC22B2B01F765055CF807D95BEF5656820099DEC2BCBB18F50E'.
    CONSTANTS c_signature_3 TYPE xstring VALUE
      '5B543D4B5475950BD9686D56FA85B9729D33259577D40912D22E441EDF50C604'.
    CONSTANTS c_signature_4 TYPE xstring VALUE
      'BB1CB0D5DB42D180360F7E73AD5E113605869663343F6BF21570BBC6DCBA087D'.

    METHODS valid_signature FOR TESTING RAISING cx_static_check.
    METHODS changed_message FOR TESTING RAISING cx_static_check.
    METHODS changed_signature FOR TESTING RAISING cx_static_check.
    METHODS modulus RETURNING VALUE(rv_n) TYPE xstring.
    METHODS signature RETURNING VALUE(rv_signature) TYPE xstring.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD modulus.
    CONCATENATE c_n_1 c_n_2 c_n_3 c_n_4 INTO rv_n IN BYTE MODE.
  ENDMETHOD.


  METHOD signature.
    CONCATENATE c_signature_1 c_signature_2 c_signature_3 c_signature_4
      INTO rv_signature IN BYTE MODE.
  ENDMETHOD.


  METHOD valid_signature.
    cl_abap_unit_assert=>assert_true( zcl_oassh_rsa=>verify_pkcs1_sha256(
      iv_n         = modulus( )
      iv_e         = c_e
      iv_signature = signature( )
      iv_message   = c_message ) ).
  ENDMETHOD.


  METHOD changed_message.
    cl_abap_unit_assert=>assert_false( zcl_oassh_rsa=>verify_pkcs1_sha256(
      iv_n         = modulus( )
      iv_e         = c_e
      iv_signature = signature( )
      iv_message   = '00' ) ).
  ENDMETHOD.


  METHOD changed_signature.
    cl_abap_unit_assert=>assert_false( zcl_oassh_rsa=>verify_pkcs1_sha256(
      iv_n         = modulus( )
      iv_e         = c_e
      iv_signature = modulus( )
      iv_message   = c_message ) ).
  ENDMETHOD.
ENDCLASS.
