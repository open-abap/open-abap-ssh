CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = zcl_oassh_message_21=>serialize( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = '15' ).
    zcl_oassh_message_21=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.
ENDCLASS.
