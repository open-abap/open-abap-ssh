CLASS zcl_oassh_hmac DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* HMAC-SHA-256 via cl_abap_hmac, one of the allowed standard classes
* (see PLAN.md): kernel-backed on any NW 7.02+ system and implemented via
* Node crypto in open-abap-core, so it is fast on both runtimes.

    CLASS-METHODS sha256
      IMPORTING
        iv_key        TYPE xstring
        iv_data       TYPE xstring
      RETURNING
        VALUE(rv_mac) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_hmac IMPLEMENTATION.


  METHOD sha256.

* SSH keys are never empty, and cl_abap_hmac degenerates to a plain hash
* for an empty key instead of using an all-zero key
    ASSERT iv_key IS NOT INITIAL.

    TRY.
        cl_abap_hmac=>calculate_hmac_for_raw(
          EXPORTING
            if_algorithm   = 'SHA256'
            if_key         = iv_key
            if_data        = iv_data
          IMPORTING
            ef_hmacxstring = rv_mac ).
      CATCH cx_abap_message_digest.
* SHA256 is supported on every kernel this runs on
        ASSERT 0 = 1.
    ENDTRY.

  ENDMETHOD.
ENDCLASS.
