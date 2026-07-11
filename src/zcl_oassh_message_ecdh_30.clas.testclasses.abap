CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_ecdh_30=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_ecdh_30=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_ecdh_30=>gc_message_id.
    ls_expected-q_c = '01020304'.
    lo_stream = zcl_oassh_message_ecdh_30=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_ecdh_30=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
  ENDMETHOD.
ENDCLASS.
