CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh_stream DEFINITION LOCAL FRIENDS ltcl_test.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_stream TYPE REF TO zcl_oassh_stream.
    METHODS setup.
    METHODS name_list FOR TESTING RAISING cx_static_check.
    METHODS empty_name_list FOR TESTING RAISING cx_static_check.
    METHODS malformed_name_lists FOR TESTING RAISING cx_static_check.
    METHODS unit32 FOR TESTING RAISING cx_static_check.
    METHODS uint32_peek FOR TESTING RAISING cx_static_check.
    METHODS uint64_zero FOR TESTING RAISING cx_static_check.
    METHODS uint64_small FOR TESTING RAISING cx_static_check.
    METHODS uint64_max_int4 FOR TESTING RAISING cx_static_check.
    METHODS uint64_rejects_low_boundary FOR TESTING RAISING cx_static_check.
    METHODS uint64_rejects_high_half FOR TESTING RAISING cx_static_check.
    METHODS uint64_rejects_truncated FOR TESTING RAISING cx_static_check.
    METHODS uint64_rejects_negative FOR TESTING RAISING cx_static_check.
    METHODS constructs_empty FOR TESTING RAISING cx_static_check.
    METHODS append_take FOR TESTING RAISING cx_static_check.
    METHODS interleaved_append_take FOR TESTING RAISING cx_static_check.
    METHODS append_after_consume FOR TESTING RAISING cx_static_check.
    METHODS many_chunks FOR TESTING RAISING cx_static_check.
    METHODS empty_appends FOR TESTING RAISING cx_static_check.
    METHODS fragmented_length FOR TESTING RAISING cx_static_check.
    METHODS clear FOR TESTING RAISING cx_static_check.
    METHODS boolean_true FOR TESTING RAISING cx_static_check.
    METHODS boolean_false FOR TESTING RAISING cx_static_check.
    METHODS boolean_roundtrip FOR TESTING RAISING cx_static_check.
    METHODS byte FOR TESTING RAISING cx_static_check.
    METHODS string FOR TESTING RAISING cx_static_check.
    METHODS mpint_zero FOR TESTING RAISING cx_static_check.
    METHODS mpint_positive FOR TESTING RAISING cx_static_check.
    METHODS mpint_high_bit FOR TESTING RAISING cx_static_check.
    METHODS mpint_strip_leading FOR TESTING RAISING cx_static_check.
    METHODS mpint_decode_test FOR TESTING RAISING cx_static_check.
    METHODS positive_rejects_negative FOR TESTING RAISING cx_static_check.
    METHODS positive_rejects_redundant FOR TESTING RAISING cx_static_check.
    METHODS take_rejects_truncated FOR TESTING RAISING cx_static_check.
    METHODS string_rejects_truncated FOR TESTING RAISING cx_static_check.
    METHODS mpint_roundtrip FOR TESTING RAISING cx_static_check.
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

  METHOD uint32_peek.

    mo_stream->uint32_encode( 42 ).

    " peek does not consume
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode_peek( )
      exp = 42 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 4 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint32_decode( )
      exp = 42 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).

  ENDMETHOD.

  METHOD uint64_zero.

    mo_stream->uint64_encode( 0 ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '0000000000000000' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint64_decode( )
      exp = 0 ).

  ENDMETHOD.

  METHOD uint64_small.

    mo_stream->uint64_encode( 32768 ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '0000000000008000' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->uint64_decode( )
      exp = 32768 ).

  ENDMETHOD.

  METHOD uint64_max_int4.
* 0x000000007FFFFFFF is the largest value that fits the int4-safe ceiling.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( '000000007FFFFFFF' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->uint64_decode( )
      exp = 2147483647 ).

    mo_stream->uint64_encode( 2147483647 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000007FFFFFFF' ).
  ENDMETHOD.

  METHOD uint64_rejects_low_boundary.
* 0x00000000FFFFFFFF: high half zero, but the low word exceeds the int4 ceiling.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '00000000FFFFFFFF' ).
    TRY.
        lo_stream->uint64_decode( ).
        cl_abap_unit_assert=>fail( 'oversized uint64 accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.

  METHOD uint64_rejects_high_half.
* Any set bit in the high 32 bits is beyond the addressable int4 range.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '0000000100000000' ).
    TRY.
        lo_stream->uint64_decode( ).
        cl_abap_unit_assert=>fail( 'high-half uint64 accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.

  METHOD uint64_rejects_truncated.
* Fewer than eight bytes available must raise, never return a partial value.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '00000000000000' ).
    TRY.
        lo_stream->uint64_decode( ).
        cl_abap_unit_assert=>fail( 'truncated uint64 accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.

  METHOD uint64_rejects_negative.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    TRY.
        mo_stream->uint64_encode( -1 ).
        cl_abap_unit_assert=>fail( 'negative uint64 accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.

  METHOD constructs_empty.

    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    CREATE OBJECT lo_stream EXPORTING iv_hex = 'ABCDEF'.

    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = 'ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 3 ).

  ENDMETHOD.

  METHOD append_take.

    mo_stream->append( '0011' ).
    mo_stream->append( '2233' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 4 ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 2 )
      exp = '0011' ).

    " take consumes from the front
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '2233' ).

  ENDMETHOD.

  METHOD interleaved_append_take.

    " models the receive buffer: bytes arrive in chunks and are framed off
    " the front while more chunks keep arriving. take() must never re-read
    " already-consumed bytes and append() must extend the unconsumed tail.
    mo_stream->append( '0011' ).
    mo_stream->append( '2233' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 3 )
      exp = '001122' ).

    " new data appended after partial consumption
    mo_stream->append( '4455' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 3 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '334455' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 3 )
      exp = '334455' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).

  ENDMETHOD.

  METHOD append_after_consume.

    " drain fully, then append again - cursor must not desync
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    CREATE OBJECT lo_stream EXPORTING iv_hex = 'AABB'.

    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->take( 2 )
      exp = 'AABB' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).

    lo_stream->append( 'CCDD' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 2 ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->take( 2 )
      exp = 'CCDD' ).

  ENDMETHOD.


  METHOD empty_name_list.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lt_names TYPE string_table.
    lo_stream = NEW #( '00000000' ).
    lt_names = lo_stream->name_list_decode( ).
    cl_abap_unit_assert=>assert_initial( lt_names ).
  ENDMETHOD.


  METHOD malformed_name_lists.
    DATA lt_fixtures TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
    DATA lv_fixture TYPE xstring.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lo_builder TYPE REF TO zcl_oassh_stream.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
* Leading, trailing, and repeated separators; whitespace/control bytes; and a
* 65-character name all violate RFC 4251's canonical name-list syntax.
    APPEND '000000022C61' TO lt_fixtures.
    APPEND '00000002612C' TO lt_fixtures.
    APPEND '00000004612C2C62' TO lt_fixtures.
    APPEND '00000003612062' TO lt_fixtures.
    APPEND '00000003610A62' TO lt_fixtures.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = '61' ).
    lo_builder = NEW #( ).
    lo_builder->string_encode( li_random->bytes( 65 ) ).
    APPEND lo_builder->get( ) TO lt_fixtures.
    LOOP AT lt_fixtures INTO lv_fixture.
      CLEAR lv_reason.
      lo_stream = NEW #( lv_fixture ).
      TRY.
          lo_stream->name_list_decode( ).
        CATCH zcx_oassh_error INTO lx_error.
          lv_reason = lx_error->if_t100_message~t100key-msgno.
      ENDTRY.
      cl_abap_unit_assert=>assert_equals(
        act = lv_reason
        exp = '003' ).
    ENDLOOP.

* The upper canonical boundary remains valid.
    lo_builder = NEW #( ).
    lo_builder->string_encode( li_random->bytes( 64 ) ).
    lo_stream = NEW #( lo_builder->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( lo_stream->name_list_decode( ) )
      exp = 1 ).
  ENDMETHOD.


  METHOD many_chunks.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_chunk TYPE xstring VALUE '0011223344556677'.
    DATA lv_expected TYPE xstring.
    DO 1024 TIMES.
      mo_stream->append( lv_chunk ).
    ENDDO.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = lv_chunk ).
    lv_expected = li_random->bytes( 8192 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = lv_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 8192 ).
  ENDMETHOD.

  METHOD empty_appends.
    DATA lv_empty TYPE xstring.
    DO 4096 TIMES.
      mo_stream->append( lv_empty ).
    ENDDO.
    cl_abap_unit_assert=>assert_initial( mo_stream->mt_pending ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD fragmented_length.
* APC receive uses fixed one-byte frames. Repeated length polling must leave
* them pending instead of copying the complete accumulated prefix each time.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA lv_expected TYPE xstring.
    DO 4096 TIMES.
      mo_stream->append( 'AB' ).
      cl_abap_unit_assert=>assert_equals(
        act = mo_stream->find_cr_lf( )
        exp = -1 ).
      cl_abap_unit_assert=>assert_equals(
        act = mo_stream->get_length( )
        exp = sy-index ).
    ENDDO.
    cl_abap_unit_assert=>assert_initial( mo_stream->mv_hex ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( mo_stream->mt_pending )
      exp = 4096 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->mv_pending_length
      exp = 4096 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->mv_line_scan_pending
      exp = 4096 ).
    mo_stream->append( '0D' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->find_cr_lf( )
      exp = -1 ).
    mo_stream->append( '0A' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->find_cr_lf( )
      exp = 4096 ).
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    lv_expected = li_random->bytes( 4096 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 4096 )
      exp = lv_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->take( 2 )
      exp = CONV xstring( zcl_oassh_ascii=>c_cr_lf ) ).
    cl_abap_unit_assert=>assert_initial( mo_stream->mt_pending ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->mv_pending_length
      exp = 0 ).

* Materializing between partial scans changes the backing layout; scanning
* must restart there and still find a later terminator correctly.
    mo_stream->append( '41' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->find_cr_lf( )
      exp = -1 ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '41' ).
    mo_stream->append( '0D0A' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->find_cr_lf( )
      exp = 1 ).
  ENDMETHOD.

  METHOD clear.

    mo_stream->append( '00112233' ).
    mo_stream->clear( ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get_length( )
      exp = 0 ).

  ENDMETHOD.

  METHOD boolean_true.

    mo_stream->boolean_encode( abap_true ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '01' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->boolean_decode( )
      exp = abap_true ).

  ENDMETHOD.

  METHOD boolean_false.

    mo_stream->boolean_encode( abap_false ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->boolean_decode( )
      exp = abap_false ).

  ENDMETHOD.

  METHOD boolean_roundtrip.

    " any non-zero byte decodes to TRUE
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    CREATE OBJECT lo_stream EXPORTING iv_hex = 'FF'.

    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->boolean_decode( )
      exp = abap_true ).

  ENDMETHOD.

  METHOD byte.

    mo_stream->byte_encode( 'AB' ).
    mo_stream->byte_encode( 'CD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = 'ABCD' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->byte_decode( )
      exp = 'AB' ).
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->byte_decode( )
      exp = 'CD' ).

  ENDMETHOD.

  METHOD string.

    DATA lv_payload TYPE xstring VALUE 'DEADBEEF'.
    mo_stream->string_encode( lv_payload ).

    " uint32 length prefix (4 bytes) + data
    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00000004DEADBEEF' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->string_decode( )
      exp = 'DEADBEEF' ).

  ENDMETHOD.

  METHOD mpint_zero.
* RFC 4251: value 0 is stored as a string with zero bytes of data
    mo_stream->mpint_encode( `` ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '00000000' ).

  ENDMETHOD.

  METHOD mpint_positive.
* RFC 4251 example: 9a378f9b2e332a7 -> 00 00 00 08 09 a3 78 f9 b2 e3 32 a7
    mo_stream->mpint_encode( '09A378F9B2E332A7' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '0000000809A378F9B2E332A7' ).

  ENDMETHOD.

  METHOD mpint_high_bit.
* RFC 4251 example: 80 -> 00 00 00 02 00 80 (zero byte prepended)
    mo_stream->mpint_encode( '80' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000020080' ).

  ENDMETHOD.

  METHOD mpint_strip_leading.
* unnecessary leading zero bytes must be removed before encoding
    mo_stream->mpint_encode( '00000080' ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->get( )
      exp = '000000020080' ).

  ENDMETHOD.

  METHOD mpint_decode_test.

    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    " high-bit value: sign byte is stripped on decode
    CREATE OBJECT lo_stream EXPORTING iv_hex = '000000020080'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '80' ).

    " plain positive value: returned unchanged
    CREATE OBJECT lo_stream EXPORTING iv_hex = '0000000809A378F9B2E332A7'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '09A378F9B2E332A7' ).

    " zero
    CREATE OBJECT lo_stream EXPORTING iv_hex = '00000000'.
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->mpint_decode( )
      exp = '' ).

  ENDMETHOD.

  METHOD mpint_roundtrip.

    DATA lv_value TYPE xstring VALUE '80'.
    mo_stream->mpint_encode( lv_value ).

    cl_abap_unit_assert=>assert_equals(
      act = mo_stream->mpint_decode( )
      exp = lv_value ).

  ENDMETHOD.


  METHOD positive_rejects_negative.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '00000001FF' ).
    TRY.
        lo_stream->mpint_decode_positive( ).
        cl_abap_unit_assert=>fail( 'negative mpint accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.


  METHOD positive_rejects_redundant.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '00000002007F' ).
    TRY.
        lo_stream->mpint_decode_positive( ).
        cl_abap_unit_assert=>fail( 'non-canonical mpint accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.


  METHOD take_rejects_truncated.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( 'AABB' ).
    TRY.
        lo_stream->take( 3 ).
        cl_abap_unit_assert=>fail( 'truncated field accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.


  METHOD string_rejects_truncated.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_stream = NEW #( '00000005AA' ).
    TRY.
        lo_stream->string_decode( ).
        cl_abap_unit_assert=>fail( 'truncated SSH string accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.

ENDCLASS.
