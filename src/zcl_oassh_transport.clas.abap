CLASS zcl_oassh_transport DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS c_kex_curve25519 TYPE string VALUE 'curve25519-sha256'.
    CONSTANTS c_kex_group14 TYPE string VALUE 'diffie-hellman-group14-sha256'.
    CONSTANTS:
      BEGIN OF c_state,
        initial      TYPE i VALUE 0,
        kexinit_sent TYPE i VALUE 1,
        ecdh_sent    TYPE i VALUE 2,
        newkeys_sent TYPE i VALUE 3,
        encrypted    TYPE i VALUE 4,
      END OF c_state.
    CONSTANTS:
      BEGIN OF c_auth_state,
        none              TYPE i VALUE 0,
        service_requested TYPE i VALUE 1,
        request_sent      TYPE i VALUE 2,
        authenticated     TYPE i VALUE 3,
      END OF c_auth_state.

    METHODS constructor
      IMPORTING
        ii_random        TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier
        iv_offer_strict  TYPE abap_bool DEFAULT abap_true
        iv_offer_group14 TYPE abap_bool DEFAULT abap_true.
    CLASS-METHODS verify_server_signature
      IMPORTING
        iv_host_key       TYPE xstring
        iv_signature      TYPE xstring
        iv_exchange_hash  TYPE xstring
      RETURNING
        VALUE(rv_verified) TYPE abap_bool.
    METHODS start_kex
      IMPORTING
        iv_client_version TYPE xstring
        iv_server_version TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS start_rekey
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS receive_kexinit
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS receive_kex_reply
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS activate_outbound_keys.
    METHODS receive_newkeys
      IMPORTING
        iv_payload TYPE xstring.
    METHODS start_auth
      IMPORTING
        iv_user           TYPE xstring
        iv_password       TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS receive_auth
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS get_auth_state
      RETURNING
        VALUE(rv_state) TYPE i.
    METHODS get_state
      RETURNING
        VALUE(rv_state) TYPE i.
    METHODS get_exchange_hash
      RETURNING
        VALUE(rv_hash) TYPE xstring.
    METHODS get_session_id
      RETURNING
        VALUE(rv_session_id) TYPE xstring.
    METHODS get_rekey_count
      RETURNING
        VALUE(rv_count) TYPE i.
    METHODS get_kex_algorithm
      RETURNING VALUE(rv_algorithm) TYPE string.
    METHODS is_strict_kex
      RETURNING
        VALUE(rv_strict) TYPE abap_bool.
    METHODS is_initial_kex
      RETURNING
        VALUE(rv_initial) TYPE abap_bool.
    METHODS get_packet
      RETURNING
        VALUE(ro_packet) TYPE REF TO zcl_oassh_packet.

  PRIVATE SECTION.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mi_host_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA mv_state TYPE i.
    DATA mv_v_c TYPE xstring.
    DATA mv_v_s TYPE xstring.
    DATA mv_i_c TYPE xstring.
    DATA mv_i_s TYPE xstring.
    DATA mv_private TYPE xstring.
    DATA mv_q_c TYPE xstring.
    DATA mv_k TYPE xstring.
    DATA mv_h TYPE xstring.
    DATA mv_session_id TYPE xstring.
    DATA mv_iv_c_to_s TYPE xstring.
    DATA mv_iv_s_to_c TYPE xstring.
    DATA mv_key_c_to_s TYPE xstring.
    DATA mv_key_s_to_c TYPE xstring.
    DATA mv_mac_c_to_s TYPE xstring.
    DATA mv_mac_s_to_c TYPE xstring.
    DATA mo_packet TYPE REF TO zcl_oassh_packet.
    DATA mv_user TYPE xstring.
    DATA mv_password TYPE xstring.
    DATA mv_auth_state TYPE i.
    DATA mv_rekey_in_progress TYPE abap_bool.
    DATA mv_rekey_count TYPE i.
    DATA mv_strict_kex TYPE abap_bool.
    DATA mv_initial_kex TYPE abap_bool.
    DATA mv_offer_strict TYPE abap_bool.
    DATA mv_offer_group14 TYPE abap_bool.
    DATA mv_kex_algorithm TYPE string.

    METHODS derive_keys.
ENDCLASS.


CLASS zcl_oassh_transport IMPLEMENTATION.

  METHOD constructor.
    mi_random = ii_random.
    mi_host_verifier = ii_host_verifier.
    mv_offer_strict = iv_offer_strict.
    mv_offer_group14 = iv_offer_group14.
  ENDMETHOD.


  METHOD verify_server_signature.
    DATA lo_host TYPE REF TO zcl_oassh_stream.
    DATA lo_signature TYPE REF TO zcl_oassh_stream.
    DATA lv_host_algorithm TYPE xstring.
    DATA lv_signature_algorithm TYPE xstring.
    DATA lv_e TYPE xstring.
    DATA lv_n TYPE xstring.
    DATA lv_signature TYPE xstring.
    lo_host = NEW #( iv_host_key ).
    lv_host_algorithm = lo_host->string_decode( ).
    IF zcl_oassh_ascii=>from_xstring( lv_host_algorithm ) <> 'ssh-rsa'.
      RETURN.
    ENDIF.
    lv_e = lo_host->mpint_decode( ).
    lv_n = lo_host->mpint_decode( ).
    IF lo_host->get_length( ) <> 0.
      RETURN.
    ENDIF.
    lo_signature = NEW #( iv_signature ).
    lv_signature_algorithm = lo_signature->string_decode( ).
    IF zcl_oassh_ascii=>from_xstring( lv_signature_algorithm ) <> 'rsa-sha2-256'.
      RETURN.
    ENDIF.
    lv_signature = lo_signature->string_decode( ).
    IF lo_signature->get_length( ) <> 0.
      RETURN.
    ENDIF.
    rv_verified = zcl_oassh_rsa=>verify_pkcs1_sha256(
      iv_n         = lv_n
      iv_e         = lv_e
      iv_signature = lv_signature
      iv_message   = iv_exchange_hash ).
  ENDMETHOD.


  METHOD start_kex.
    DATA ls_kexinit TYPE zcl_oassh_message_20=>ty_data.
    ASSERT mv_state = c_state-initial.
    mv_v_c = iv_client_version.
    mv_v_s = iv_server_version.
    ls_kexinit = zcl_oassh_message_20=>create( mi_random ).
    IF mv_offer_group14 = abap_false.
      DELETE ls_kexinit-kex_algorithms WHERE table_line = c_kex_group14.
    ENDIF.
* Offer both the standard and widely deployed OpenSSH strict-KEX markers.
    IF mv_offer_strict = abap_true.
      APPEND 'kex-strict-c' TO ls_kexinit-kex_algorithms.
      APPEND 'kex-strict-c-v00@openssh.com' TO ls_kexinit-kex_algorithms.
    ENDIF.
    rv_payload = zcl_oassh_message_20=>serialize( ls_kexinit )->get( ).
    mv_i_c = rv_payload.
    mv_initial_kex = abap_true.
    mv_state = c_state-kexinit_sent.
  ENDMETHOD.


  METHOD start_rekey.
* Server-initiated rekey: reply with a fresh client KEXINIT while the current
* packet keys remain active. Version strings and the original session id stay.
    DATA ls_kexinit TYPE zcl_oassh_message_20=>ty_data.
    ASSERT mv_state = c_state-encrypted.
    ASSERT mv_session_id IS NOT INITIAL.
    ls_kexinit = zcl_oassh_message_20=>create( mi_random ).
    IF mv_offer_group14 = abap_false.
      DELETE ls_kexinit-kex_algorithms WHERE table_line = c_kex_group14.
    ENDIF.
    rv_payload = zcl_oassh_message_20=>serialize( ls_kexinit )->get( ).
    mv_i_c = rv_payload.
    mv_rekey_in_progress = abap_true.
    mv_state = c_state-kexinit_sent.
  ENDMETHOD.


  METHOD receive_kexinit.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_ecdh TYPE zcl_oassh_message_ecdh_30=>ty_data.
    DATA ls_dh TYPE zcl_oassh_message_dh_30=>ty_data.
    ASSERT mv_state = c_state-kexinit_sent.
    lo_stream = NEW #( iv_payload ).
    ls_server = zcl_oassh_message_20=>parse( lo_stream ).
    ASSERT lo_stream->get_length( ) = 0.
* RFC 4253 section 7.1 selects the first client-preferred common method.
    IF line_exists( ls_server-kex_algorithms[ table_line = c_kex_curve25519 ] ).
      mv_kex_algorithm = c_kex_curve25519.
    ELSEIF mv_offer_group14 = abap_true
        AND line_exists( ls_server-kex_algorithms[ table_line = c_kex_group14 ] ).
      mv_kex_algorithm = c_kex_group14.
    ELSE.
      ASSERT 1 = 2.
    ENDIF.
    ASSERT line_exists( ls_server-server_host_key_algorithms[ table_line = 'rsa-sha2-256' ] ).
    ASSERT line_exists( ls_server-encryption_algorithms_c_to_s[ table_line = 'aes128-ctr' ] ).
    ASSERT line_exists( ls_server-encryption_algorithms_s_to_c[ table_line = 'aes128-ctr' ] ).
    ASSERT line_exists( ls_server-mac_algorithms_c_to_s[ table_line = 'hmac-sha2-256' ] ).
    ASSERT line_exists( ls_server-mac_algorithms_s_to_c[ table_line = 'hmac-sha2-256' ] ).
    ASSERT line_exists( ls_server-compression_algorithms_c_to_s[ table_line = 'none' ] ).
    ASSERT line_exists( ls_server-compression_algorithms_s_to_c[ table_line = 'none' ] ).
    IF mv_initial_kex = abap_true.
      mv_strict_kex = xsdbool( mv_offer_strict = abap_true
        AND ( line_exists( ls_server-kex_algorithms[ table_line = 'kex-strict-s' ] )
          OR line_exists( ls_server-kex_algorithms[ table_line = 'kex-strict-s-v00@openssh.com' ] ) ) ).
    ENDIF.
    mv_i_s = iv_payload.
    mv_private = mi_random->bytes( 32 ).
    IF mv_kex_algorithm = c_kex_curve25519.
      mv_q_c = zcl_oassh_x25519=>scalarmult_base( mv_private ).
      ls_ecdh-message_id = zcl_oassh_message_ecdh_30=>gc_message_id.
      ls_ecdh-q_c = mv_q_c.
      rv_payload = zcl_oassh_message_ecdh_30=>serialize( ls_ecdh )->get( ).
    ELSE.
* A 256-bit exponent supplies more than twice group14's ~112-bit strength.
      IF zcl_oassh_bigint=>compare(
          iv_a = mv_private
          iv_b = '01' ) <= 0.
        mv_private = '02'.
      ENDIF.
      mv_q_c = zcl_oassh_group14=>public_key( mv_private ).
      ls_dh-message_id = zcl_oassh_message_dh_30=>gc_message_id.
      ls_dh-e = mv_q_c.
      rv_payload = zcl_oassh_message_dh_30=>serialize( ls_dh )->get( ).
    ENDIF.
    mv_state = c_state-ecdh_sent.
  ENDMETHOD.


  METHOD derive_keys.
    mv_iv_c_to_s = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'A'
      iv_session_id = mv_session_id
      iv_length     = 16 ).
    mv_iv_s_to_c = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'B'
      iv_session_id = mv_session_id
      iv_length     = 16 ).
    mv_key_c_to_s = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'C'
      iv_session_id = mv_session_id
      iv_length     = 16 ).
    mv_key_s_to_c = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'D'
      iv_session_id = mv_session_id
      iv_length     = 16 ).
    mv_mac_c_to_s = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'E'
      iv_session_id = mv_session_id
      iv_length     = 32 ).
    mv_mac_s_to_c = zcl_oassh_kdf=>derive_key(
      iv_k          = mv_k
      iv_h          = mv_h
      iv_letter     = 'F'
      iv_session_id = mv_session_id
      iv_length     = 32 ).
  ENDMETHOD.


  METHOD receive_kex_reply.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_ecdh TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA ls_dh TYPE zcl_oassh_message_dh_31=>ty_data.
    DATA lv_shared_le TYPE xstring.
    DATA lv_host_key TYPE xstring.
    DATA lv_server_public TYPE xstring.
    DATA lv_signature TYPE xstring.
    ASSERT mv_state = c_state-ecdh_sent.
    lo_stream = NEW #( iv_payload ).
    IF mv_kex_algorithm = c_kex_curve25519.
      ls_ecdh = zcl_oassh_message_ecdh_31=>parse( lo_stream ).
      ASSERT xstrlen( ls_ecdh-q_s ) = 32.
      lv_host_key = ls_ecdh-k_s.
      lv_server_public = ls_ecdh-q_s.
      lv_signature = ls_ecdh-signature.
      lv_shared_le = zcl_oassh_x25519=>scalarmult(
        iv_scalar = mv_private
        iv_u      = lv_server_public ).
* RFC 8731 encodes the X25519 octet string directly as an SSH mpint.
      mv_k = lv_shared_le.
      mv_h = zcl_oassh_kdf=>exchange_hash(
        iv_v_c = mv_v_c
        iv_v_s = mv_v_s
        iv_i_c = mv_i_c
        iv_i_s = mv_i_s
        iv_k_s = lv_host_key
        iv_q_c = mv_q_c
        iv_q_s = lv_server_public
        iv_k   = mv_k ).
    ELSE.
      ls_dh = zcl_oassh_message_dh_31=>parse( lo_stream ).
      ASSERT zcl_oassh_group14=>is_valid_public( ls_dh-f ) = abap_true.
      lv_host_key = ls_dh-k_s.
      lv_server_public = ls_dh-f.
      lv_signature = ls_dh-signature.
      mv_k = zcl_oassh_group14=>shared_secret(
        iv_peer_public = lv_server_public
        iv_private     = mv_private ).
      mv_h = zcl_oassh_kdf=>exchange_hash_dh(
        iv_v_c = mv_v_c
        iv_v_s = mv_v_s
        iv_i_c = mv_i_c
        iv_i_s = mv_i_s
        iv_k_s = lv_host_key
        iv_e   = mv_q_c
        iv_f   = lv_server_public
        iv_k   = mv_k ).
    ENDIF.
    ASSERT lo_stream->get_length( ) = 0.
    ASSERT mi_host_verifier->verify( lv_host_key ) = abap_true.
    ASSERT verify_server_signature(
      iv_host_key      = lv_host_key
      iv_signature     = lv_signature
      iv_exchange_hash = mv_h ) = abap_true.
    IF mv_session_id IS INITIAL.
      mv_session_id = mv_h.
    ENDIF.
    derive_keys( ).
    rv_payload = zcl_oassh_message_21=>serialize( )->get( ).
    mv_state = c_state-newkeys_sent.
  ENDMETHOD.


  METHOD receive_newkeys.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_was_initial TYPE abap_bool.
    ASSERT mv_state = c_state-newkeys_sent.
    lv_was_initial = mv_initial_kex.
    lo_stream = NEW #( iv_payload ).
    zcl_oassh_message_21=>parse( lo_stream ).
    ASSERT lo_stream->get_length( ) = 0.
    ASSERT mo_packet IS BOUND.
    mo_packet->rekey_decrypt(
      iv_decrypt_key = mv_key_s_to_c
      iv_decrypt_iv  = mv_iv_s_to_c
      iv_decrypt_mac = mv_mac_s_to_c ).
    IF mv_strict_kex = abap_true.
      mo_packet->reset_receive_sequence( ).
    ENDIF.
    IF mv_rekey_in_progress = abap_true.
      mv_rekey_count = mv_rekey_count + 1.
      CLEAR mv_rekey_in_progress.
    ENDIF.
    IF lv_was_initial = abap_true.
      CLEAR mv_initial_kex.
    ENDIF.
    mv_state = c_state-encrypted.
  ENDMETHOD.


  METHOD activate_outbound_keys.
    DATA lv_sequence TYPE i VALUE 3.
* The NEWKEYS payload itself is sent with the old keys. Call this immediately
* after that packet has been encoded and handed to the socket.
    ASSERT mv_state = c_state-newkeys_sent.
    IF mv_strict_kex = abap_true.
      CLEAR lv_sequence.
    ENDIF.
    IF mo_packet IS NOT BOUND.
      mo_packet = NEW #(
        ii_random           = mi_random
        iv_encrypt_key      = mv_key_c_to_s
        iv_encrypt_iv       = mv_iv_c_to_s
        iv_encrypt_mac      = mv_mac_c_to_s
        iv_send_sequence    = lv_sequence
        iv_receive_sequence = lv_sequence ).
    ELSE.
      mo_packet->rekey_encrypt(
        iv_encrypt_key = mv_key_c_to_s
        iv_encrypt_iv  = mv_iv_c_to_s
        iv_encrypt_mac = mv_mac_c_to_s ).
      IF mv_strict_kex = abap_true.
        mo_packet->reset_send_sequence( ).
      ENDIF.
    ENDIF.
  ENDMETHOD.


  METHOD start_auth.
* https://datatracker.ietf.org/doc/html/rfc4253#section-10
* request the ssh-userauth service; the password method follows in receive_auth
    DATA ls_data TYPE zcl_oassh_message_5=>ty_data.
    ASSERT mv_state = c_state-encrypted.
    mv_user = iv_user.
    mv_password = iv_password.
    ls_data-message_id = zcl_oassh_message_5=>gc_message_id.
    ls_data-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-userauth' ).
    rv_payload = zcl_oassh_message_5=>serialize( ls_data )->get( ).
    mv_auth_state = c_auth_state-service_requested.
  ENDMETHOD.


  METHOD receive_auth.
* https://datatracker.ietf.org/doc/html/rfc4252
    DATA lv_id TYPE x LENGTH 1.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_accept TYPE zcl_oassh_message_6=>ty_data.
    DATA ls_request TYPE zcl_oassh_message_50=>ty_data.
    lv_id = iv_payload(1).
    lo_stream = NEW #( iv_payload ).
    CASE lv_id.
      WHEN zcl_oassh_message_6=>gc_message_id.
        ASSERT mv_auth_state = c_auth_state-service_requested.
        ls_accept = zcl_oassh_message_6=>parse( lo_stream ).
        ASSERT zcl_oassh_ascii=>from_xstring( ls_accept-service_name ) = 'ssh-userauth'.
        ls_request-message_id = zcl_oassh_message_50=>gc_message_id.
        ls_request-user_name = mv_user.
        ls_request-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
        ls_request-method_name = zcl_oassh_ascii=>to_xstring( 'password' ).
        ls_request-password = mv_password.
        rv_payload = zcl_oassh_message_50=>serialize( ls_request )->get( ).
        mv_auth_state = c_auth_state-request_sent.
      WHEN zcl_oassh_message_53=>gc_message_id.
* USERAUTH_BANNER: informational only, no reply
        zcl_oassh_message_53=>parse( lo_stream ).
      WHEN zcl_oassh_message_52=>gc_message_id.
        zcl_oassh_message_52=>parse( lo_stream ).
        mv_auth_state = c_auth_state-authenticated.
      WHEN zcl_oassh_message_51=>gc_message_id.
* USERAUTH_FAILURE: password rejected (or more methods required)
        zcl_oassh_message_51=>parse( lo_stream ).
        ASSERT 1 = 2.
      WHEN OTHERS.
        ASSERT 1 = 2.
    ENDCASE.
  ENDMETHOD.


  METHOD get_auth_state.
    rv_state = mv_auth_state.
  ENDMETHOD.


  METHOD get_state.
    rv_state = mv_state.
  ENDMETHOD.


  METHOD get_exchange_hash.
    rv_hash = mv_h.
  ENDMETHOD.


  METHOD get_session_id.
    rv_session_id = mv_session_id.
  ENDMETHOD.


  METHOD get_rekey_count.
    rv_count = mv_rekey_count.
  ENDMETHOD.


  METHOD get_kex_algorithm.
    rv_algorithm = mv_kex_algorithm.
  ENDMETHOD.


  METHOD is_strict_kex.
    rv_strict = mv_strict_kex.
  ENDMETHOD.


  METHOD is_initial_kex.
    rv_initial = mv_initial_kex.
  ENDMETHOD.


  METHOD get_packet.
    ro_packet = mo_packet.
  ENDMETHOD.
ENDCLASS.
