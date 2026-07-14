CLASS zcl_oassh_sha512 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CLASS-METHODS hash
      IMPORTING iv_data        TYPE xstring
      RETURNING VALUE(rv_hash) TYPE xstring.
ENDCLASS.

CLASS zcl_oassh_sha512 IMPLEMENTATION.
  METHOD hash.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_raw(
          EXPORTING
            if_algorithm   = 'SHA512'
            if_data        = iv_data
          IMPORTING
            ef_hashxstring = rv_hash ).
      CATCH cx_abap_message_digest.
        ASSERT 0 = 1.
    ENDTRY.
  ENDMETHOD.
ENDCLASS.
