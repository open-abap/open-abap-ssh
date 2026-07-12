CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    METHODS roundtrip FOR TESTING RAISING cx_static_check.
    METHODS wire_format FOR TESTING RAISING cx_static_check.
    METHODS publickey_wire FOR TESTING RAISING cx_static_check.
    METHODS signed_publickey FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD roundtrip.
    DATA ls_expected TYPE zcl_oassh_message_50=>ty_data.
    DATA ls_actual TYPE zcl_oassh_message_50=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_expected-message_id = zcl_oassh_message_50=>gc_message_id.
    ls_expected-user_name = zcl_oassh_ascii=>to_xstring( 'bob' ).
    ls_expected-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_expected-method_name = zcl_oassh_ascii=>to_xstring( 'password' ).
    ls_expected-password = zcl_oassh_ascii=>to_xstring( 'secret' ).
    lo_stream = zcl_oassh_message_50=>serialize( ls_expected ).
    ls_actual = zcl_oassh_message_50=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_actual
      exp = ls_expected ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD wire_format.
* byte-exact layout: 0x32, string "a", string "ssh-connection",
* string "password", boolean FALSE, string "pw"
    DATA ls_data TYPE zcl_oassh_message_50=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_data-message_id = zcl_oassh_message_50=>gc_message_id.
    ls_data-user_name = zcl_oassh_ascii=>to_xstring( 'a' ).
    ls_data-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_data-method_name = zcl_oassh_ascii=>to_xstring( 'password' ).
    ls_data-password = zcl_oassh_ascii=>to_xstring( 'pw' ).
    lo_stream = zcl_oassh_message_50=>serialize( ls_data ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = '3200000001610000000E7373682D636F6E6E656374696F6E0000000870617373776F726400000000027077' ).
  ENDMETHOD.


  METHOD publickey_wire.
    DATA ls_data TYPE zcl_oassh_message_50=>ty_publickey.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    ls_data-message_id = zcl_oassh_message_50=>gc_message_id.
    ls_data-user_name = zcl_oassh_ascii=>to_xstring( 'test' ).
    ls_data-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_data-method_name = zcl_oassh_ascii=>to_xstring( 'publickey' ).
    ls_data-algorithm = zcl_oassh_ascii=>to_xstring( 'ssh-ed25519' ).
    ls_data-public_key = '0102'.
    ls_data-signature = '0304'.
    lo_stream = zcl_oassh_message_50=>serialize_publickey( ls_data ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get( )
      exp = '3200000004746573740000000E7373682D636F6E6E656374696F6E'
        && '000000097075626C69636B6579010000000B7373682D65643235353139'
        && '000000020102000000020304' ).
  ENDMETHOD.


  METHOD signed_publickey.
    DATA lv_seed TYPE xstring VALUE
      '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60'.
    DATA lv_session TYPE xstring VALUE '01020304'.
    DATA lv_payload TYPE xstring.
    DATA lv_signature TYPE xstring.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lo_key TYPE REF TO zcl_oassh_stream.
    DATA lo_signature TYPE REF TO zcl_oassh_stream.
    DATA lo_signed TYPE REF TO zcl_oassh_stream.
    DATA ls_data TYPE zcl_oassh_message_50=>ty_publickey.
    lv_payload = zcl_oassh_message_50=>signed_publickey_request(
      iv_user         = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_session_id   = lv_session
      iv_private_seed = lv_seed ).
    lo_stream = NEW #( lv_payload ).
    ls_data-message_id = lo_stream->take( 1 ).
    ls_data-user_name = lo_stream->string_decode( ).
    ls_data-service_name = lo_stream->string_decode( ).
    ls_data-method_name = lo_stream->string_decode( ).
    cl_abap_unit_assert=>assert_true( lo_stream->boolean_decode( ) ).
    ls_data-algorithm = lo_stream->string_decode( ).
    ls_data-public_key = lo_stream->string_decode( ).
    ls_data-signature = lo_stream->string_decode( ).
    lo_key = NEW #( ls_data-public_key ).
    lo_key->string_decode( ).
    lo_signature = NEW #( ls_data-signature ).
    lo_signature->string_decode( ).
    lv_signature = lo_signature->string_decode( ).
    CLEAR ls_data-signature.
    lo_signed = NEW #( ).
    lo_signed->string_encode( lv_session ).
    lo_signed->append( zcl_oassh_message_50=>serialize_publickey_unsigned( ls_data )->get( ) ).
    cl_abap_unit_assert=>assert_true(
      zcl_oassh_ed25519=>verify(
        iv_public_key = lo_key->string_decode( )
        iv_message    = lo_signed->get( )
        iv_signature  = lv_signature ) ).
  ENDMETHOD.
ENDCLASS.
