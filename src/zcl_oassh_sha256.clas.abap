CLASS zcl_oassh_sha256 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* SHA-256 via cl_abap_message_digest, one of the allowed standard classes
* (see PLAN.md): kernel-backed on any NW 7.02+ system and implemented via
* Node crypto in open-abap-core, so it is fast on both runtimes.

    CLASS-METHODS hash
      IMPORTING
        iv_data        TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_sha256 IMPLEMENTATION.


  METHOD hash.

    TRY.
        cl_abap_message_digest=>calculate_hash_for_raw(
          EXPORTING
            if_algorithm   = 'SHA256'
            if_data        = iv_data
          IMPORTING
            ef_hashxstring = rv_hash ).
      CATCH cx_abap_message_digest.
* SHA256 is supported on every kernel this runs on
        ASSERT 0 = 1.
    ENDTRY.

  ENDMETHOD.
ENDCLASS.
