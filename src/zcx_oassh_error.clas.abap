CLASS zcx_oassh_error DEFINITION
  PUBLIC
  INHERITING FROM cx_static_check
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS:
      BEGIN OF c_reason,
        timeout          TYPE i VALUE 1,
        packet_too_large TYPE i VALUE 2,
        malformed_packet TYPE i VALUE 3,
        mac_invalid      TYPE i VALUE 4,
        negotiation_failed TYPE i VALUE 5,
        host_key_rejected TYPE i VALUE 6,
        signature_invalid TYPE i VALUE 7,
        invalid_credentials TYPE i VALUE 8,
      END OF c_reason.
    METHODS constructor
      IMPORTING
        iv_reason TYPE i.
    METHODS get_reason
      RETURNING
        VALUE(rv_reason) TYPE i.
    CLASS-METHODS raise
      IMPORTING
        iv_reason TYPE i
      RAISING
        zcx_oassh_error.

  PRIVATE SECTION.
    DATA mv_reason TYPE i.
ENDCLASS.


CLASS zcx_oassh_error IMPLEMENTATION.
  METHOD constructor.
    super->constructor( ).
    mv_reason = iv_reason.
  ENDMETHOD.


  METHOD get_reason.
    rv_reason = mv_reason.
  ENDMETHOD.


  METHOD raise.
    RAISE EXCEPTION TYPE zcx_oassh_error
      EXPORTING
        iv_reason = iv_reason.
  ENDMETHOD.
ENDCLASS.
