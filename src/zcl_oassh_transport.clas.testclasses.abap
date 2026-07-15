CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh_transport DEFINITION LOCAL FRIENDS ltcl_test.

CLASS lcl_verifier DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
    METHODS received RETURNING VALUE(rv_host_key) TYPE xstring.
    METHODS received_host RETURNING VALUE(rv_host) TYPE string.
    METHODS received_port RETURNING VALUE(rv_port) TYPE string.
  PRIVATE SECTION.
    DATA mv_received TYPE xstring.
    DATA mv_received_host TYPE string.
    DATA mv_received_port TYPE string.
ENDCLASS.


CLASS lcl_verifier IMPLEMENTATION.
  METHOD received.
    rv_host_key = mv_received.
  ENDMETHOD.


  METHOD received_host.
    rv_host = mv_received_host.
  ENDMETHOD.


  METHOD received_port.
    rv_port = mv_received_port.
  ENDMETHOD.


  METHOD zif_oassh_host_verifier~verify.
    mv_received_host = iv_host.
    mv_received_port = iv_port.
    mv_received = iv_host_key.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.


CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.
  PRIVATE SECTION.
    TYPES ty_payloads TYPE STANDARD TABLE OF xstring WITH EMPTY KEY.
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
    CONSTANTS c_exchange_hash TYPE xstring VALUE
      '2EB36772C13530C22D335FD21E0244DB92A99A9F41027C6198581CD2A2F395D4'.
    METHODS through_newkeys FOR TESTING RAISING cx_static_check.
    METHODS password_auth FOR TESTING RAISING cx_static_check.
    METHODS empty_password FOR TESTING RAISING cx_static_check.
    METHODS handshake
      RETURNING VALUE(ro_transport) TYPE REF TO zcl_oassh_transport
      RAISING cx_static_check.
    METHODS kex_pending
      RETURNING VALUE(ro_transport) TYPE REF TO zcl_oassh_transport
      RAISING cx_static_check.
    METHODS valid_kex_reply RETURNING VALUE(rv_payload) TYPE xstring.
    METHODS signature_ok FOR TESTING RAISING cx_static_check.
    METHODS signature_tampered_hash FOR TESTING RAISING cx_static_check.
    METHODS signature_wrong_host_algo FOR TESTING RAISING cx_static_check.
    METHODS signature_wrong_sig_algo FOR TESTING RAISING cx_static_check.
    METHODS signature_noncanonical_names FOR TESTING RAISING cx_static_check.
    METHODS signature_negotiated_mismatch FOR TESTING RAISING cx_static_check.
    METHODS negotiation_rejected FOR TESTING RAISING cx_static_check.
    METHODS invalid_private_seed FOR TESTING RAISING cx_static_check.
    METHODS invalid_group14_public FOR TESTING RAISING cx_static_check.
    METHODS invalid_x25519_public FOR TESTING RAISING cx_static_check.
    METHODS premature_auth_reply FOR TESTING RAISING cx_static_check.
    METHODS malformed_auth_is_atomic FOR TESTING RAISING cx_static_check.
    METHODS malformed_kex_is_atomic FOR TESTING RAISING cx_static_check.
    METHODS invalid_signature_not_trusted FOR TESTING RAISING cx_static_check.
    METHODS noncanonical_auth_service FOR TESTING RAISING cx_static_check.
    METHODS authentication_failure FOR TESTING RAISING cx_static_check.
    METHODS credential_fallback FOR TESTING RAISING cx_static_check.
    METHODS rekey FOR TESTING RAISING cx_static_check.
    METHODS strict_kex FOR TESTING RAISING cx_static_check.
    METHODS guessed_kex_packet FOR TESTING RAISING cx_static_check.
    METHODS group14_fallback FOR TESTING RAISING cx_static_check.
    METHODS chacha_fallback FOR TESTING RAISING cx_static_check.
    METHODS host_endpoint FOR TESTING RAISING cx_static_check.
    METHODS clear_secrets FOR TESTING RAISING cx_static_check.
    METHODS host_key RETURNING VALUE(rv_host_key) TYPE xstring.
    METHODS signature_bytes RETURNING VALUE(rv_signature) TYPE xstring.
    METHODS signature_blob RETURNING VALUE(rv_signature) TYPE xstring.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.
  METHOD host_endpoint.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    lo_transport = handshake( ).
    lo_verifier ?= lo_transport->mi_host_verifier.
    cl_abap_unit_assert=>assert_equals(
      act = lo_verifier->received_host( )
      exp = 'test.example' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_verifier->received_port( )
      exp = '22' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_verifier->received( )
      exp = host_key( ) ).
  ENDMETHOD.


  METHOD host_key.
    CONCATENATE c_host_1 c_host_2 c_host_3 c_host_4 c_host_5
      INTO rv_host_key IN BYTE MODE.
  ENDMETHOD.


  METHOD signature_bytes.
    CONCATENATE c_sig_1 c_sig_2 c_sig_3 c_sig_4
      INTO rv_signature IN BYTE MODE.
  ENDMETHOD.


  METHOD signature_blob.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'rsa-sha2-256' ) ).
    lo_stream->string_encode( signature_bytes( ) ).
    rv_signature = lo_stream->get( ).
  ENDMETHOD.


  METHOD handshake.
    ro_transport = kex_pending( ).
    ro_transport->receive_kex_reply( valid_kex_reply( ) ).
    ro_transport->activate_outbound_keys( ).
    ro_transport->receive_newkeys( zcl_oassh_message_21=>serialize( )->get( ) ).
  ENDMETHOD.


  METHOD kex_pending.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    ro_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false
      iv_offer_group14 = abap_false
      iv_offer_chacha  = abap_false
      iv_offer_ed25519 = abap_false ).
    ro_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-server_host_key_algorithms
      WHERE table_line = zcl_oassh_transport=>c_host_ed25519.
    DELETE ls_server-kex_algorithms WHERE table_line = zcl_oassh_transport=>c_kex_group14.
    DELETE ls_server-encryption_algorithms_c_to_s
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    DELETE ls_server-encryption_algorithms_s_to_c
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    ro_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
  ENDMETHOD.


  METHOD valid_kex_reply.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    ls_reply-message_id = zcl_oassh_message_ecdh_31=>gc_message_id.
    ls_reply-k_s = host_key( ).
    ls_reply-q_s = 'CABC16BA515B878A3F17A2E5ECBD86FAE1554EA1559ACD496A22F45127652A68'.
    ls_reply-signature = signature_blob( ).
    rv_payload = zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ).
  ENDMETHOD.


  METHOD password_auth.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lv_payload TYPE xstring.
    DATA lv_message_id TYPE x LENGTH 1.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_banner TYPE zcl_oassh_message_53=>ty_data.

    lo_transport = handshake( ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-encrypted ).

    lv_payload = lo_transport->start_auth(
      iv_user     = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password = zcl_oassh_ascii=>to_xstring( 'test' ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_5=>gc_message_id ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-service_requested ).

* SERVICE_ACCEPT triggers the password USERAUTH_REQUEST
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_accept-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_6=>serialize( ls_accept )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_50=>gc_message_id ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-request_sent ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_password ).
    cl_abap_unit_assert=>assert_false( lo_transport->mv_password_supplied ).

* a banner in between is informational: no reply, state unchanged
    ls_banner-message_id = zcl_oassh_message_53=>gc_message_id.
    ls_banner-message = zcl_oassh_ascii=>to_xstring( 'hello' ).
    ls_banner-language_tag = zcl_oassh_ascii=>to_xstring( 'en' ).
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_53=>serialize( ls_banner )->get( ) ).
    cl_abap_unit_assert=>assert_initial( lv_payload ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-request_sent ).

* USERAUTH_SUCCESS completes authentication
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_52=>serialize( )->get( ) ).
    cl_abap_unit_assert=>assert_initial( lv_payload ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-authenticated ).
  ENDMETHOD.


  METHOD signature_ok.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = host_key( )
        iv_signature     = signature_blob( )
        iv_exchange_hash = c_exchange_hash )
      exp = abap_true ).
  ENDMETHOD.


  METHOD signature_tampered_hash.
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = host_key( )
        iv_signature     = signature_blob( )
        iv_exchange_hash = '00' )
      exp = abap_false ).
  ENDMETHOD.


  METHOD signature_wrong_host_algo.
* An "ssh-dss" host key must be rejected before any RSA math runs.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'ssh-dss' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = lo_stream->get( )
        iv_signature     = signature_blob( )
        iv_exchange_hash = c_exchange_hash )
      exp = abap_false ).
  ENDMETHOD.


  METHOD signature_wrong_sig_algo.
* Legacy "ssh-rsa" (SHA-1) signatures are not accepted; only rsa-sha2-256.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->string_encode( zcl_oassh_ascii=>to_xstring( 'ssh-rsa' ) ).
    lo_stream->string_encode( signature_bytes( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = host_key( )
        iv_signature     = lo_stream->get( )
        iv_exchange_hash = c_exchange_hash )
      exp = abap_false ).
  ENDMETHOD.


  METHOD signature_negotiated_mismatch.
* A valid RSA wrapper cannot satisfy an ssh-ed25519 negotiation.
    cl_abap_unit_assert=>assert_false(
      zcl_oassh_transport=>verify_server_signature(
        iv_host_key           = host_key( )
        iv_signature          = signature_blob( )
        iv_exchange_hash      = c_exchange_hash
        iv_expected_algorithm = zcl_oassh_transport=>c_host_ed25519 ) ).
  ENDMETHOD.


  METHOD negotiation_rejected.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-server' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    CLEAR ls_server-kex_algorithms.
    TRY.
        lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
        cl_abap_unit_assert=>fail( 'missing common KEX accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '005' ).
    ENDTRY.

* An algorithm deliberately omitted from the client proposal cannot become
* "common" merely because the server advertises it.
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_ed25519 = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-server' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    CLEAR ls_server-server_host_key_algorithms.
    APPEND zcl_oassh_transport=>c_host_ed25519
      TO ls_server-server_host_key_algorithms.
    TRY.
        lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
        cl_abap_unit_assert=>fail( 'unoffered host-key algorithm accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '005' ).
    ENDTRY.
  ENDMETHOD.


  METHOD empty_password.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_request TYPE zcl_oassh_message_50=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_empty_password TYPE xstring.
    DATA lv_payload TYPE xstring.
    DATA lv_reason TYPE symsgno.
    lo_random = NEW #( iv_pattern = '01' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lo_transport->mv_state = zcl_oassh_transport=>c_state-encrypted.

* RFC 4252 section 8 defines the password as an SSH string and does not
* require it to be non-empty. Explicit presence is separate from its value.
    lo_transport->start_auth(
      iv_user              = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password          = lv_empty_password
      iv_password_supplied = abap_true ).
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_accept-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_6=>serialize( ls_accept )->get( ) ).
    lo_stream = NEW #( lv_payload ).
    ls_request = zcl_oassh_message_50=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_initial( ls_request-password ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).

* Omitting both supported credential forms remains an API error.
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lo_transport->mv_state = zcl_oassh_transport=>c_state-encrypted.
    TRY.
        lo_transport->start_auth(
          iv_user              = zcl_oassh_ascii=>to_xstring( 'test' )
          iv_password_supplied = abap_false ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '008' ).
  ENDMETHOD.


  METHOD invalid_private_seed.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lo_transport->mv_state = zcl_oassh_transport=>c_state-encrypted.
    TRY.
        lo_transport->start_auth(
          iv_user         = zcl_oassh_ascii=>to_xstring( 'test' )
          iv_password     = zcl_oassh_ascii=>to_xstring( 'fallback' )
          iv_private_seed = '01' ).
        cl_abap_unit_assert=>fail( 'malformed private seed accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '008' ).
    ENDTRY.
  ENDMETHOD.


  METHOD invalid_group14_public.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_reply TYPE zcl_oassh_message_dh_31=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-server' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-kex_algorithms WHERE table_line = zcl_oassh_transport=>c_kex_curve25519.
    lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    ls_reply-message_id = zcl_oassh_message_dh_31=>gc_message_id.
    ls_reply-f = '01'.
    TRY.
        lo_transport->receive_kex_reply( zcl_oassh_message_dh_31=>serialize( ls_reply )->get( ) ).
        cl_abap_unit_assert=>fail( 'invalid group14 public value accepted' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '003' ).
    ENDTRY.
  ENDMETHOD.


  METHOD authentication_failure.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_failure TYPE zcl_oassh_message_51=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    lo_transport = handshake( ).
    lo_transport->start_auth(
      iv_user     = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password = zcl_oassh_ascii=>to_xstring( 'test' ) ).
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_accept-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lo_transport->receive_auth( zcl_oassh_message_6=>serialize( ls_accept )->get( ) ).
    ls_failure-message_id = zcl_oassh_message_51=>gc_message_id.
    APPEND 'password' TO ls_failure-authentications.
    TRY.
        lo_transport->receive_auth( zcl_oassh_message_51=>serialize( ls_failure )->get( ) ).
        cl_abap_unit_assert=>fail( 'authentication failure ignored' ).
      CATCH zcx_oassh_error INTO lx_error.
        cl_abap_unit_assert=>assert_equals(
          act = lx_error->if_t100_message~t100key-msgno
          exp = '009' ).
    ENDTRY.
  ENDMETHOD.


  METHOD through_newkeys.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lv_payload TYPE xstring.
    DATA lv_message_id TYPE x LENGTH 1.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.

    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false
      iv_offer_group14 = abap_false
      iv_offer_chacha  = abap_false
      iv_offer_ed25519 = abap_false ).
    lv_payload = lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_20=>gc_message_id
      msg = 'initial KEXINIT message' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-kexinit_sent
      msg = 'state after initial KEXINIT' ).

    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-server_host_key_algorithms
      WHERE table_line = zcl_oassh_transport=>c_host_ed25519.
    DELETE ls_server-kex_algorithms WHERE table_line = zcl_oassh_transport=>c_kex_group14.
    DELETE ls_server-encryption_algorithms_c_to_s
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    DELETE ls_server-encryption_algorithms_s_to_c
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    lv_payload = lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_ecdh_30=>gc_message_id
      msg = 'ECDH init message' ).

    ls_reply-message_id = zcl_oassh_message_ecdh_31=>gc_message_id.
    ls_reply-k_s = host_key( ).
    ls_reply-q_s = 'CABC16BA515B878A3F17A2E5ECBD86FAE1554EA1559ACD496A22F45127652A68'.
    ls_reply-signature = signature_blob( ).
    lv_payload = lo_transport->receive_kex_reply(
      zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_21=>gc_message_id
      msg = 'NEWKEYS reply' ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lv_payload )
      exp = 1
      msg = 'NEWKEYS payload length' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_exchange_hash( )
      exp = lo_transport->get_session_id( )
      msg = 'first exchange hash is session id' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_exchange_hash( )
      exp = '2EB36772C13530C22D335FD21E0244DB92A99A9F41027C6198581CD2A2F395D4'
      msg = 'fixed Curve25519 exchange hash' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_verifier->received( )
      exp = host_key( )
      msg = 'host verifier input' ).
    cl_abap_unit_assert=>assert_not_initial( lo_transport->get_exchange_hash( ) ).

    lo_transport->activate_outbound_keys( ).
    lo_transport->receive_newkeys( zcl_oassh_message_21=>serialize( )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-encrypted
      msg = 'encrypted state after NEWKEYS' ).
    lo_packet = lo_transport->get_packet( ).
    cl_abap_unit_assert=>assert_bound( lo_packet ).
    cl_abap_unit_assert=>assert_not_initial( lo_packet->encode( '05' ) ).
  ENDMETHOD.


  METHOD rekey.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_packet TYPE REF TO zcl_oassh_packet.
    DATA lo_server_random TYPE REF TO zcl_oassh_random_fixed.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lv_payload TYPE xstring.
    DATA lv_message_id TYPE x LENGTH 1.
    DATA lv_session_id TYPE xstring.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_client TYPE zcl_oassh_message_20=>ty_data.

    lo_transport = handshake( ).
    lo_packet = lo_transport->get_packet( ).
    lv_session_id = lo_transport->get_session_id( ).

    lo_server_random = NEW #( iv_pattern = '0102030405060708' ).
    ls_server = zcl_oassh_message_20=>create( lo_server_random ).
    DELETE ls_server-server_host_key_algorithms
      WHERE table_line = zcl_oassh_transport=>c_host_ed25519.
    DELETE ls_server-kex_algorithms WHERE table_line = zcl_oassh_transport=>c_kex_group14.
    DELETE ls_server-encryption_algorithms_c_to_s
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    DELETE ls_server-encryption_algorithms_s_to_c
      WHERE table_line = zcl_oassh_transport=>c_cipher_chachapoly.
    lv_payload = lo_transport->start_rekey( ).
    lo_stream = NEW #( lv_payload ).
    ls_client = zcl_oassh_message_20=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_false(
      xsdbool( line_exists(
        ls_client-kex_algorithms[ table_line = zcl_oassh_transport=>c_kex_group14 ] ) ) ).
    cl_abap_unit_assert=>assert_false(
      xsdbool( line_exists(
        ls_client-encryption_algorithms_c_to_s[
          table_line = zcl_oassh_transport=>c_cipher_chachapoly ] ) ) ).
    cl_abap_unit_assert=>assert_false(
      xsdbool( line_exists(
        ls_client-server_host_key_algorithms[
          table_line = zcl_oassh_transport=>c_host_ed25519 ] ) ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_20=>gc_message_id
      msg = 'rekey KEXINIT message' ).
    lv_payload = lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_ecdh_30=>gc_message_id
      msg = 'rekey ECDH init message' ).

    ls_reply-message_id = zcl_oassh_message_ecdh_31=>gc_message_id.
    ls_reply-k_s = host_key( ).
    ls_reply-q_s = 'CABC16BA515B878A3F17A2E5ECBD86FAE1554EA1559ACD496A22F45127652A68'.
    ls_reply-signature = signature_blob( ).
    lv_payload = lo_transport->receive_kex_reply(
      zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_21=>gc_message_id
      msg = 'rekey NEWKEYS reply' ).
    cl_abap_unit_assert=>assert_equals(
      act = xstrlen( lv_payload )
      exp = 1
      msg = 'rekey NEWKEYS payload length' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_session_id( )
      exp = lv_session_id
      msg = 'rekey preserves session id' ).

    lo_transport->activate_outbound_keys( ).
    lo_transport->receive_newkeys( zcl_oassh_message_21=>serialize( )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-encrypted
      msg = 'encrypted state after rekey' ).
    cl_abap_unit_assert=>assert_true( xsdbool( lo_transport->get_packet( ) = lo_packet ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_rekey_count( )
      exp = 1
      msg = 'rekey count' ).
  ENDMETHOD.


  METHOD strict_kex.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_client TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_payload TYPE xstring.

    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lv_payload = lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    lo_stream = NEW #( lv_payload ).
    ls_client = zcl_oassh_message_20=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists( ls_client-kex_algorithms[ table_line = 'kex-strict-c' ] ) ) ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists(
        ls_client-kex_algorithms[ table_line = 'kex-strict-c-v00@openssh.com' ] ) ) ).

    ls_server = zcl_oassh_message_20=>create( lo_random ).
    APPEND 'kex-strict-s-v00@openssh.com' TO ls_server-kex_algorithms.
    lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    cl_abap_unit_assert=>assert_true( lo_transport->is_strict_kex( ) ).
    cl_abap_unit_assert=>assert_true( lo_transport->is_initial_kex( ) ).
  ENDMETHOD.


  METHOD credential_fallback.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_failure TYPE zcl_oassh_message_51=>ty_data.
    DATA ls_password TYPE zcl_oassh_message_50=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_payload TYPE xstring.
    DATA lv_message_id TYPE x LENGTH 1.
    DATA lv_seed TYPE xstring VALUE
      '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60'.
    DATA lv_reason TYPE symsgno.
    lo_transport = handshake( ).
    lo_transport->start_auth(
      iv_user              = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password          = zcl_oassh_ascii=>to_xstring( 'fallback' )
      iv_password_supplied = abap_true
      iv_private_seed      = lv_seed ).
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_accept-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_6=>serialize( ls_accept )->get( ) ).
    lv_message_id = lv_payload(1).
    cl_abap_unit_assert=>assert_equals(
      act = lv_message_id
      exp = zcl_oassh_message_50=>gc_message_id ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_private_seed ).
    cl_abap_unit_assert=>assert_not_initial( lo_transport->mv_password ).

* The server rejects publickey but explicitly permits password to continue.
    ls_failure-message_id = zcl_oassh_message_51=>gc_message_id.
    APPEND 'password' TO ls_failure-authentications.
    lv_payload = lo_transport->receive_auth( zcl_oassh_message_51=>serialize( ls_failure )->get( ) ).
    lo_stream = NEW #( lv_payload ).
    ls_password = zcl_oassh_message_50=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_password-password
      exp = zcl_oassh_ascii=>to_xstring( 'fallback' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_password ).
    cl_abap_unit_assert=>assert_false( lo_transport->mv_password_supplied ).

* A rejected fallback is terminal even if the server repeats "password".
    TRY.
        lo_transport->receive_auth( zcl_oassh_message_51=>serialize( ls_failure )->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '009' ).
  ENDMETHOD.


  METHOD clear_secrets.
    CONSTANTS lc_key TYPE xstring VALUE '2B7E151628AED2A6ABF7158809CF4F3C'.
    CONSTANTS lc_iv TYPE xstring VALUE 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    CONSTANTS lc_mac TYPE xstring VALUE '0102030405060708090A0B0C0D0E0F10'.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    lo_random = NEW #( iv_pattern = '01' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22' ).
    lo_transport->mv_private = '01'.
    lo_transport->mv_k = '02'.
    lo_transport->mv_iv_c_to_s = lc_iv.
    lo_transport->mv_iv_s_to_c = lc_iv.
    lo_transport->mv_key_c_to_s = lc_key.
    lo_transport->mv_key_s_to_c = lc_key.
    lo_transport->mv_mac_c_to_s = lc_mac.
    lo_transport->mv_mac_s_to_c = lc_mac.
    lo_transport->mv_password = '03'.
    lo_transport->mv_password_supplied = abap_true.
    lo_transport->mv_private_seed = '04'.
    lo_transport->mo_packet = NEW #(
      ii_random      = lo_random
      iv_encrypt_key = lc_key
      iv_encrypt_iv  = lc_iv
      iv_encrypt_mac = lc_mac
      iv_decrypt_key = lc_key
      iv_decrypt_iv  = lc_iv
      iv_decrypt_mac = lc_mac ).

    lo_transport->clear_secrets( ).

    cl_abap_unit_assert=>assert_initial( lo_transport->mv_private ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_k ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_iv_c_to_s ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_iv_s_to_c ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_key_c_to_s ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_key_s_to_c ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_mac_c_to_s ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_mac_s_to_c ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_password ).
    cl_abap_unit_assert=>assert_false( lo_transport->mv_password_supplied ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_private_seed ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->mo_packet->get_auth_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD signature_noncanonical_names.
    DATA lo_source TYPE REF TO zcl_oassh_stream.
    DATA lo_malformed TYPE REF TO zcl_oassh_stream.
    DATA lv_e TYPE xstring.
    DATA lv_n TYPE xstring.
    DATA lv_signature TYPE xstring.
    lo_source = NEW #( host_key( ) ).
    lo_source->string_decode( ).
    lv_e = lo_source->mpint_decode( ).
    lv_n = lo_source->mpint_decode( ).

* Filtering must not turn ssh-<NUL>rsa into the canonical ssh-rsa token.
    lo_malformed = NEW #( ).
    lo_malformed->string_encode( '7373682D00727361' ).
    lo_malformed->mpint_encode( lv_e ).
    lo_malformed->mpint_encode( lv_n ).
    cl_abap_unit_assert=>assert_false(
      zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = lo_malformed->get( )
        iv_signature     = signature_blob( )
        iv_exchange_hash = c_exchange_hash ) ).

* The signature wrapper algorithm is also compared as exact wire bytes.
    lo_malformed = NEW #( ).
    lo_malformed->string_encode( '7273612D736861322D00323536' ).
    lo_malformed->string_encode( signature_bytes( ) ).
    lv_signature = lo_malformed->get( ).
    cl_abap_unit_assert=>assert_false(
      zcl_oassh_transport=>verify_server_signature(
        iv_host_key      = host_key( )
        iv_signature     = lv_signature
        iv_exchange_hash = c_exchange_hash ) ).
  ENDMETHOD.


  METHOD premature_auth_reply.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lt_payloads TYPE ty_payloads.
    DATA ls_banner TYPE zcl_oassh_message_53=>ty_data.
    DATA ls_failure TYPE zcl_oassh_message_51=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_transport = handshake( ).
    lo_transport->start_auth(
      iv_user     = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password = zcl_oassh_ascii=>to_xstring( 'test' ) ).
    ls_banner-message_id = zcl_oassh_message_53=>gc_message_id.
    ls_banner-message = zcl_oassh_ascii=>to_xstring( 'premature' ).
    ls_failure-message_id = zcl_oassh_message_51=>gc_message_id.
    APPEND 'password' TO ls_failure-authentications.
    APPEND zcl_oassh_message_53=>serialize( ls_banner )->get( ) TO lt_payloads.
    APPEND zcl_oassh_message_52=>serialize( )->get( ) TO lt_payloads.
    APPEND zcl_oassh_message_51=>serialize( ls_failure )->get( ) TO lt_payloads.

    LOOP AT lt_payloads INTO DATA(lv_payload).
      CLEAR lv_reason.
      TRY.
          lo_transport->receive_auth( lv_payload ).
        CATCH zcx_oassh_error INTO lx_error.
          lv_reason = lx_error->if_t100_message~t100key-msgno.
      ENDTRY.
      cl_abap_unit_assert=>assert_equals(
        act = lv_reason
        exp = '003' ).
      cl_abap_unit_assert=>assert_equals(
        act = lo_transport->get_auth_state( )
        exp = zcl_oassh_transport=>c_auth_state-service_requested ).
    ENDLOOP.
  ENDMETHOD.


  METHOD malformed_auth_is_atomic.
* Trailing bytes must be rejected before credentials or auth state are spent.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_accept TYPE xstring.
    DATA lv_malformed TYPE xstring.
    DATA lv_reason TYPE symsgno.
    lo_transport = handshake( ).
    lo_transport->start_auth(
      iv_user              = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password          = zcl_oassh_ascii=>to_xstring( 'secret' )
      iv_password_supplied = abap_true ).
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
    ls_accept-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    lv_accept = zcl_oassh_message_6=>serialize( ls_accept )->get( ).
    lv_malformed = lv_accept && 'AA'.

    TRY.
        lo_transport->receive_auth( lv_malformed ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-service_requested ).
    cl_abap_unit_assert=>assert_true( lo_transport->mv_password_supplied ).

    lo_transport->receive_auth( lv_accept ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-request_sent ).

    CLEAR lv_reason.
    TRY.
        lo_transport->receive_auth( '34AA' ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-request_sent ).

    lo_transport->receive_auth( '34' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-authenticated ).
  ENDMETHOD.


  METHOD malformed_kex_is_atomic.
* Unauthenticated or structurally malformed replies must not publish K or H.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reply TYPE xstring.
    DATA lv_malformed TYPE xstring.
    DATA lv_reason TYPE symsgno.
    lo_transport = kex_pending( ).
    lv_reply = valid_kex_reply( ).
    lv_malformed = lv_reply && 'AA'.
    TRY.
        lo_transport->receive_kex_reply( lv_malformed ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
    cl_abap_unit_assert=>assert_initial( lo_transport->get_exchange_hash( ) ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_k ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-ecdh_sent ).

* The valid authenticated reply can still complete after malformed rejection.
    lo_transport->receive_kex_reply( lv_reply ).
    cl_abap_unit_assert=>assert_not_initial( lo_transport->get_exchange_hash( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-newkeys_sent ).
  ENDMETHOD.


  METHOD invalid_signature_not_trusted.
* A trust/TOFU callback must never see a key without valid possession proof.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_transport = kex_pending( ).
    lo_verifier ?= lo_transport->mi_host_verifier.
    lo_stream = NEW #( valid_kex_reply( ) ).
    ls_reply = zcl_oassh_message_ecdh_31=>parse( lo_stream ).
    ls_reply-signature = '00'.
    TRY.
        lo_transport->receive_kex_reply( zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '007' ).
    cl_abap_unit_assert=>assert_initial( lo_verifier->received( ) ).
    cl_abap_unit_assert=>assert_initial( lo_transport->get_exchange_hash( ) ).
    cl_abap_unit_assert=>assert_initial( lo_transport->mv_k ).
  ENDMETHOD.


  METHOD noncanonical_auth_service.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_transport = handshake( ).
    lo_transport->start_auth(
      iv_user     = zcl_oassh_ascii=>to_xstring( 'test' )
      iv_password = zcl_oassh_ascii=>to_xstring( 'test' ) ).
    ls_accept-message_id = zcl_oassh_message_6=>gc_message_id.
* Filtering previously normalized ssh-<NUL>userauth to ssh-userauth.
    ls_accept-service_name = '7373682D007573657261757468'.
    TRY.
        lo_transport->receive_auth( zcl_oassh_message_6=>serialize( ls_accept )->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_auth_state( )
      exp = zcl_oassh_transport=>c_auth_state-service_requested ).
  ENDMETHOD.


  METHOD invalid_x25519_public.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE symsgno.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-server' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    ls_reply-message_id = zcl_oassh_message_ecdh_31=>gc_message_id.
    ls_reply-q_s =
      '0000000000000000000000000000000000000000000000000000000000000000'.
    TRY.
        lo_transport->receive_kex_reply( zcl_oassh_message_ecdh_31=>serialize( ls_reply )->get( ) ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->if_t100_message~t100key-msgno.
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = '003' ).
  ENDMETHOD.


  METHOD guessed_kex_packet.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-server' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-kex_algorithms
      WHERE table_line = zcl_oassh_transport=>c_kex_group14.
    INSERT zcl_oassh_transport=>c_kex_group14
      INTO ls_server-kex_algorithms INDEX 1.
    DELETE ls_server-server_host_key_algorithms
      WHERE table_line = zcl_oassh_transport=>c_host_ed25519.
    INSERT zcl_oassh_transport=>c_host_ed25519
      INTO ls_server-server_host_key_algorithms INDEX 1.
    ls_server-first_kex_packet_follows = abap_true.
    lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).

* The client still selects its own preferred curve25519/RSA pair, so the
* server's group14/Ed25519 guessed packet is discarded exactly once.
    cl_abap_unit_assert=>assert_true( lo_transport->discard_guessed_packet( ) ).
    cl_abap_unit_assert=>assert_false( lo_transport->discard_guessed_packet( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_state( )
      exp = zcl_oassh_transport=>c_state-ecdh_sent ).
  ENDMETHOD.


  METHOD group14_fallback.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_dh TYPE zcl_oassh_message_dh_30=>ty_data.
    DATA lv_payload TYPE xstring.
    DATA lv_server_payload TYPE xstring.

    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-kex_algorithms WHERE table_line = zcl_oassh_transport=>c_kex_curve25519.

    lv_server_payload = zcl_oassh_message_20=>serialize( ls_server )->get( ).
    lv_payload = lo_transport->receive_kexinit( lv_server_payload ).

    lo_stream = NEW #( lv_payload ).
    ls_dh = zcl_oassh_message_dh_30=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_kex_algorithm( )
      exp = zcl_oassh_transport=>c_kex_group14 ).
    cl_abap_unit_assert=>assert_true( zcl_oassh_group14=>is_valid_public( ls_dh-e ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_stream->get_length( )
      exp = 0 ).
  ENDMETHOD.


  METHOD chacha_fallback.
    DATA lo_random TYPE REF TO zcl_oassh_random_fixed.
    DATA lo_transport TYPE REF TO zcl_oassh_transport.
    DATA lo_verifier TYPE REF TO lcl_verifier.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    lo_random = NEW #( iv_pattern = '0102030405060708' ).
    lo_verifier = NEW #( ).
    lo_transport = NEW #(
      ii_random        = lo_random
      ii_host_verifier = lo_verifier
      iv_host          = 'test.example'
      iv_port          = '22'
      iv_offer_strict  = abap_false ).
    lo_transport->start_kex(
      iv_client_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' )
      iv_server_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ) ).
    ls_server = zcl_oassh_message_20=>create( lo_random ).
    DELETE ls_server-encryption_algorithms_c_to_s
      WHERE table_line = zcl_oassh_transport=>c_cipher_aes128_ctr.
    DELETE ls_server-encryption_algorithms_s_to_c
      WHERE table_line = zcl_oassh_transport=>c_cipher_aes128_ctr.
    lo_transport->receive_kexinit( zcl_oassh_message_20=>serialize( ls_server )->get( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_transport->get_cipher_algorithm( )
      exp = zcl_oassh_transport=>c_cipher_chachapoly ).
  ENDMETHOD.
ENDCLASS.
