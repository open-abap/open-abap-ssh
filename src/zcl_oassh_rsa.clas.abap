CLASS zcl_oassh_rsa DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CLASS-METHODS verify_pkcs1_sha256
      IMPORTING
        iv_n              TYPE xstring
        iv_e              TYPE xstring
        iv_signature      TYPE xstring
        iv_message        TYPE xstring
      RETURNING
        VALUE(rv_verified) TYPE abap_bool.
ENDCLASS.


CLASS zcl_oassh_rsa IMPLEMENTATION.

  METHOD verify_pkcs1_sha256.
* EMSA-PKCS1-v1_5 with the SHA-256 DigestInfo prefix from RFC 8017.
    CONSTANTS lc_digest_info TYPE xstring VALUE
      '3031300D060960864801650304020105000420'.
    DATA lv_modulus_length TYPE i.
    DATA lv_padding_length TYPE i.
    DATA lv_decoded TYPE xstring.
    DATA lv_expected TYPE xstring.
    DATA lv_hash TYPE xstring.
    DATA lv_zero TYPE x LENGTH 1 VALUE '00'.
    DATA lv_one TYPE x LENGTH 1 VALUE '01'.
    DATA lv_ff TYPE x LENGTH 1 VALUE 'FF'.

    lv_modulus_length = xstrlen( iv_n ).
    IF lv_modulus_length < 62 OR iv_e IS INITIAL OR iv_signature IS INITIAL.
      RETURN.
    ENDIF.
    IF zcl_oassh_bigint=>compare(
        iv_a = iv_signature
        iv_b = iv_n ) >= 0.
      RETURN.
    ENDIF.

    lv_decoded = zcl_oassh_bigint=>mod_pow(
      iv_base = iv_signature
      iv_exp  = iv_e
      iv_m    = iv_n ).
    WHILE xstrlen( lv_decoded ) < lv_modulus_length.
      CONCATENATE lv_zero lv_decoded INTO lv_decoded IN BYTE MODE.
    ENDWHILE.

    lv_hash = zcl_oassh_sha256=>hash( iv_message ).
    lv_padding_length = lv_modulus_length - xstrlen( lc_digest_info ) - xstrlen( lv_hash ) - 3.
    IF lv_padding_length < 8.
      RETURN.
    ENDIF.
    CONCATENATE lv_zero lv_one INTO lv_expected IN BYTE MODE.
    DO lv_padding_length TIMES.
      CONCATENATE lv_expected lv_ff INTO lv_expected IN BYTE MODE.
    ENDDO.
    CONCATENATE lv_expected lv_zero lc_digest_info lv_hash
      INTO lv_expected IN BYTE MODE.
    rv_verified = xsdbool( lv_decoded = lv_expected ).
  ENDMETHOD.
ENDCLASS.
