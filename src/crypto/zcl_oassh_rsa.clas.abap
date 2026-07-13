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
    DATA lv_offset TYPE i.
    DATA lv_last TYPE x LENGTH 1.
    DATA lv_bit TYPE c LENGTH 1.
    DATA lv_exponent_compare TYPE i.
    DATA lv_exponent_modulus_compare TYPE i.
    DATA lv_first TYPE x LENGTH 1.
    DATA lv_most_significant_bit TYPE c LENGTH 1.

    lv_modulus_length = xstrlen( iv_n ).
    lv_exponent_compare = zcl_oassh_bigint=>compare(
      iv_a = iv_e
      iv_b = '03' ).
    lv_exponent_modulus_compare = zcl_oassh_bigint=>compare(
      iv_a = iv_e
      iv_b = iv_n ).
* RFC 8017 section 3.1 requires 3 <= e <= n - 1. Reject malformed or
* unreasonable RSA public values before attacker-sized exponentiation work.
* OpenSSH's interoperability floor is 1024 bits; cap accepted host keys at
* 8192 bits so one packet cannot trigger quadratic work on a huge modulus.
    IF lv_modulus_length < 128 OR lv_modulus_length > 1024
        OR iv_e IS INITIAL OR iv_signature IS INITIAL
        OR lv_exponent_compare < 0 OR lv_exponent_modulus_compare >= 0.
      RETURN.
    ENDIF.
* A canonical 128-byte integer may still contain only 1017..1023 bits.
* Enforce the actual 1024-bit floor, not merely its rounded octet length.
    IF lv_modulus_length = 128.
      lv_first = iv_n(1).
      GET BIT 1 OF lv_first INTO lv_most_significant_bit.
      IF lv_most_significant_bit <> '1'.
        RETURN.
      ENDIF.
    ENDIF.
    lv_offset = lv_modulus_length - 1.
    lv_last = iv_n+lv_offset(1).
    GET BIT 8 OF lv_last INTO lv_bit.
    IF lv_bit <> '1'.
      RETURN.
    ENDIF.
    lv_offset = xstrlen( iv_e ) - 1.
    lv_last = iv_e+lv_offset(1).
    GET BIT 8 OF lv_last INTO lv_bit.
    IF lv_bit <> '1'.
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
