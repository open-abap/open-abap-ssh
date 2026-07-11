CLASS lcl_verifier DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
    METHODS received RETURNING VALUE(rv_host_key) TYPE xstring.
  PRIVATE SECTION.
    DATA mv_received TYPE xstring.
ENDCLASS.


CLASS lcl_verifier IMPLEMENTATION.
  METHOD received.
    rv_host_key = mv_received.
  ENDMETHOD.


  METHOD zif_oassh_host_verifier~verify.
    mv_received = iv_host_key.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.


CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    CONSTANTS c_host_1 TYPE xstring VALUE
      '000000077373682D727361000000030100010000008100EACC6C23ED94569C9F'.
    CONSTANTS c_host_2 TYPE xstring VALUE
      'C88B8EECFF5715D5187153DEB4CE912A590C762A55C02660E01101C6C1560F4F'.
    CONSTANTS c_host_3 TYPE xstring VALUE
      'A2F0131AC43E5DC40F29622C49CC8944897ED662930D9DFFC89969FB9991440F'.
    CONSTANTS c_host_4 TYPE xstring VALUE
      'C8E66A3AC4D57AF4BB7A0B0FE90E6993CCED58C270ECAB38744A50953F4486A2'.
    CONSTANTS c_host_5 TYPE xstring VALUE
      'CDFCB9A5A1BC491CB721A8255CFDF140C7477B0B873529'.
    CONSTANTS c_sig_1 TYPE xstring VALUE
      '42AC2E0078A5C0BB1333A41F036EC8AE22C48D17800D51A075BAC90CDC1FB001'.
    CONSTANTS c_sig_2 TYPE xstring VALUE
      'B0F1E1CB6719E42C47BC26E3B86528546814C609F5EEDCD7EB454C61A4D3CF40'.
    CONSTANTS c_sig_3 TYPE xstring VALUE
      'D1E5E91C6E6AE54A16BFA1AEFE1180541A064CCBF06953F8DF237702FCE823EE'.
    CONSTANTS c_sig_4 TYPE xstring VALUE
      '9E107D795AE9161BEAA42EAEC32F116851270B6B7CE9B60A8C01150D8E64789D'.
    METHODS through_newkeys FOR TESTING RAISING cx_static_check.
    METHODS host_key RETURNING VALUE(rv_host_key) TYPE xstring.
    METHODS signature_blob RETURNING VALUE(rv_signature) TYPE xstring.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD host_key.
    CONCATENATE c_host_1 c_host_2 c_host_3 c_host_4 c_host_5
      INTO rv_host_key IN BYTE MODE.
  ENDMETHOD.


  METHOD signature_blob.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_signature TYPE xstring.
    CONCATENATE c_sig_1 c_sig_2 c_sig_3 c_sig_4
      INTO lv_signature IN BYTE MODE.
    lo_stream = NEW #( ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'rsa-sha2-256' ) ).
    lo_stream->string_encode( lv_signature ).
    rv_signature = lo_stream->get( ).
  ENDMETHOD.


  METHOD through_newkeys.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lv_payload TYPE xstring.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.

    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier ).
    lv_payload = lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_payload(1)
      exp = zcl_oassh_message_20=>gc_message_id ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-kexinit_sent ).

    ls_server = zcl_oassh_message_20=>create( lo_random ).
    lv_payload = lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_payload(1)
      exp = zcl_oassh_message_ecdh_30=>gc_message_id ).

    ls_reply-message_id = zcl_oassh_message_ecdh_31=>gc_message_id.
    ls_reply-k_s = host_key( ).
    ls_reply-q_s = 'CABC16BA515B878A3F17A2E5ECBD86FAE1554EA1559ACD496A22F45127652A68'.
    ls_reply-signature = signature_blob( ).
    lv_payload = lo_transport->receive_ecdh_reply(
      zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_payload
      exp = zcl_oassh_message_21=>gc_message_id ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_exchange_hash( )
      exp = lo_transport->get_session_id( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_exchange_hash( )
      exp = '2EB36772C13530C22D335FD21E0244DB92A99A9F41027C6198581CD2A2F395D4' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_verifier->received( )
      exp = host_key( ) ).
    cl_abap_unit_assert=>assert_not_initial( lo_transport->get_exchange_hash( ) ).

    lo_transport->receive_newkeys( zcl_oassh_message_21=>serialize( )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-encrypted ).
    lo_packet = lo_transport->get_packet( ).
    cl_abap_unit_assert=>assert_bound( lo_packet ).
    cl_abap_unit_assert=>assert_not_initial( lo_packet->encode( '05' ) ).
  ENDMETHOD.
ENDCLASS.
