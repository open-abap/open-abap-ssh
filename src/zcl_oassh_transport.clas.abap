CLASS zcl_oassh_transport DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS:
      BEGIN OF c_state,
        initial      TYPE i VALUE 0,
        kexinit_sent TYPE i VALUE 1,
        ecdh_sent    TYPE i VALUE 2,
        newkeys_sent TYPE i VALUE 3,
        encrypted    TYPE i VALUE 4,
      END OF c_state.

    METHODS constructor
      IMPORTING
        ii_random        TYPE REF TO zif_oassh_random
        ii_host_verifier TYPE REF TO zif_oassh_host_verifier.
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
    METHODS receive_kexinit
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS receive_ecdh_reply
      IMPORTING
        iv_payload        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring.
    METHODS receive_newkeys
      IMPORTING
        iv_payload TYPE xstring.
    METHODS get_state
      RETURNING
        VALUE(rv_state) TYPE i.
    METHODS get_exchange_hash
      RETURNING
        VALUE(rv_hash) TYPE xstring.
    METHODS get_session_id
      RETURNING
        VALUE(rv_session_id) TYPE xstring.
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

    METHODS derive_keys.
ENDCLASS.


CLASS zcl_oassh_transport IMPLEMENTATION.

  METHOD constructor.
    mi_random = ii_random.
    mi_host_verifier = ii_host_verifier.
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
    rv_payload = zcl_oassh_message_20=>serialize( ls_kexinit )->get( ).
    mv_i_c = rv_payload.
    mv_state = c_state-kexinit_sent.
  ENDMETHOD.


  METHOD receive_kexinit.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_server TYPE zcl_oassh_message_20=>ty_data.
    DATA ls_ecdh TYPE zcl_oassh_message_ecdh_30=>ty_data.
    ASSERT mv_state = c_state-kexinit_sent.
    lo_stream = NEW #( iv_payload ).
    ls_server = zcl_oassh_message_20=>parse( lo_stream ).
    ASSERT lo_stream->get_length( ) = 0.
    ASSERT line_exists( ls_server-kex_algorithms[ table_line = 'curve25519-sha256' ] ).
    ASSERT line_exists( ls_server-server_host_key_algorithms[ table_line = 'rsa-sha2-256' ] ).
    ASSERT line_exists( ls_server-encryption_algorithms_c_to_s[ table_line = 'aes128-ctr' ] ).
    ASSERT line_exists( ls_server-encryption_algorithms_s_to_c[ table_line = 'aes128-ctr' ] ).
    ASSERT line_exists( ls_server-mac_algorithms_c_to_s[ table_line = 'hmac-sha2-256' ] ).
    ASSERT line_exists( ls_server-mac_algorithms_s_to_c[ table_line = 'hmac-sha2-256' ] ).
    ASSERT line_exists( ls_server-compression_algorithms_c_to_s[ table_line = 'none' ] ).
    ASSERT line_exists( ls_server-compression_algorithms_s_to_c[ table_line = 'none' ] ).
    mv_i_s = iv_payload.
    mv_private = mi_random->bytes( 32 ).
    mv_q_c = zcl_oassh_x25519=>scalarmult_base( mv_private ).
    ls_ecdh-message_id = zcl_oassh_message_ecdh_30=>gc_message_id.
    ls_ecdh-q_c = mv_q_c.
    rv_payload = zcl_oassh_message_ecdh_30=>serialize( ls_ecdh )->get( ).
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


  METHOD receive_ecdh_reply.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_reply TYPE zcl_oassh_message_ecdh_31=>ty_data.
    DATA lv_shared_le TYPE xstring.
    ASSERT mv_state = c_state-ecdh_sent.
    lo_stream = NEW #( iv_payload ).
    ls_reply = zcl_oassh_message_ecdh_31=>parse( lo_stream ).
    ASSERT lo_stream->get_length( ) = 0.
    ASSERT xstrlen( ls_reply-q_s ) = 32.
    lv_shared_le = zcl_oassh_x25519=>scalarmult(
      iv_scalar = mv_private
      iv_u      = ls_reply-q_s ).
* RFC 8731 encodes the X25519 octet string directly as an SSH mpint.
    mv_k = lv_shared_le.
    mv_h = zcl_oassh_kdf=>exchange_hash(
      iv_v_c = mv_v_c
      iv_v_s = mv_v_s
      iv_i_c = mv_i_c
      iv_i_s = mv_i_s
      iv_k_s = ls_reply-k_s
      iv_q_c = mv_q_c
      iv_q_s = ls_reply-q_s
      iv_k   = mv_k ).
    ASSERT mi_host_verifier->verify( ls_reply-k_s ) = abap_true.
    ASSERT verify_server_signature(
      iv_host_key      = ls_reply-k_s
      iv_signature     = ls_reply-signature
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
    ASSERT mv_state = c_state-newkeys_sent.
    lo_stream = NEW #( iv_payload ).
    zcl_oassh_message_21=>parse( lo_stream ).
    ASSERT lo_stream->get_length( ) = 0.
    mo_packet = NEW #(
      ii_random           = mi_random
      iv_encrypt_key      = mv_key_c_to_s
      iv_encrypt_iv       = mv_iv_c_to_s
      iv_encrypt_mac      = mv_mac_c_to_s
      iv_decrypt_key      = mv_key_s_to_c
      iv_decrypt_iv       = mv_iv_s_to_c
      iv_decrypt_mac      = mv_mac_s_to_c
      iv_send_sequence    = 3
      iv_receive_sequence = 3 ).
    mv_state = c_state-encrypted.
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


  METHOD get_packet.
    ro_packet = mo_packet.
  ENDMETHOD.
ENDCLASS.
