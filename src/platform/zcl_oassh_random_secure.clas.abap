CLASS zcl_oassh_random_secure DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES zif_oassh_random.
ENDCLASS.


CLASS zcl_oassh_random_secure IMPLEMENTATION.
  METHOD zif_oassh_random~bytes.
* GENERATE_SEC_RANDOM delegates to the SAP kernel secure random generator.
* Never substitute the deterministic ABAP random-number classes here: these
* bytes include ephemeral SSH key material (RFC 4251 section 9.1).
    ASSERT iv_length > 0.

    CALL FUNCTION 'GENERATE_SEC_RANDOM'
      EXPORTING
        length         = iv_length
      IMPORTING
        random         = rv_hex
      EXCEPTIONS
        invalid_length = 1
        no_memory      = 2
        internal_error = 3
        OTHERS         = 4.

* The random interface predates checked error propagation. Fail closed rather
* than continuing a cryptographic operation with absent or truncated entropy.
    ASSERT sy-subrc = 0.
    ASSERT xstrlen( rv_hex ) = iv_length.
  ENDMETHOD.
ENDCLASS.
