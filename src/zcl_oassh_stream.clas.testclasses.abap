CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    METHODS setup.
    METHODS name_list FOR TESTING RAISING cx_static_check.
    METHODS unit32 FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD setup.
    CREATE OBJECT mo_stream.
  ENDMETHOD.

  METHOD name_list.

    DATA lt_list TYPE string_table.
    APPEND 'zlib' TO lt_list.
    APPEND 'none' TO lt_list.

    mo_stream->name_list_encode( lt_list ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000097A6C69622C6E6F6E65' ).

    cl_abap_unit_assert=>assert_equals(
      act = lines( mo_stream->name_list_decode( ) )
      exp = 2 ).

  ENDMETHOD.

  METHOD unit32.

    DATA lv_int TYPE i VALUE 699921578.

    mo_stream->uint32_encode( lv_int ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '29B7F4AA' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode( )
      exp = 699921578 ).

  ENDMETHOD.

ENDCLASS.
