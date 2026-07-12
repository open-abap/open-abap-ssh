CLASS zcl_oassh_kdf DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* Exchange hash and key derivation for the transport layer,
* RFC 4253 sections 7.2 and 8, on top of zcl_oassh_sha256.
* The negotiated kex hash is SHA-256 (curve25519-sha256 /
* diffie-hellman-group14-sha256), so this class is SHA-256 specific.

    CLASS-METHODS exchange_hash
      IMPORTING
        iv_v_c         TYPE xstring
        iv_v_s         TYPE xstring
        iv_i_c         TYPE xstring
        iv_i_s         TYPE xstring
        iv_k_s         TYPE xstring
        iv_q_c         TYPE xstring
        iv_q_s         TYPE xstring
        iv_k           TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE xstring.

    CLASS-METHODS derive_key
      IMPORTING
        iv_k          TYPE xstring
        iv_h          TYPE xstring
        iv_letter     TYPE c
        iv_session_id TYPE xstring
        iv_length     TYPE i
      RETURNING
        VALUE(rv_key) TYPE xstring.

    CLASS-METHODS exchange_hash_dh
      IMPORTING
        iv_v_c TYPE xstring
        iv_v_s TYPE xstring
        iv_i_c TYPE xstring
        iv_i_s TYPE xstring
        iv_k_s TYPE xstring
        iv_e   TYPE xstring
        iv_f   TYPE xstring
        iv_k   TYPE xstring
      RETURNING VALUE(rv_hash) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_kdf IMPLEMENTATION.


  METHOD exchange_hash_dh.
* RFC 4253 section 8:
*   H = HASH(string V_C || string V_S || string I_C || string I_S ||
*            string K_S || mpint e || mpint f || mpint K)
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->string_encode( iv_v_c ).
    lo_stream->string_encode( iv_v_s ).
    lo_stream->string_encode( iv_i_c ).
    lo_stream->string_encode( iv_i_s ).
    lo_stream->string_encode( iv_k_s ).
    lo_stream->mpint_encode( iv_e ).
    lo_stream->mpint_encode( iv_f ).
    lo_stream->mpint_encode( iv_k ).
    rv_hash = zcl_oassh_sha256=>hash( lo_stream->get( ) ).
  ENDMETHOD.


  METHOD exchange_hash.
* RFC 4253 section 8 / RFC 5656 section 4:
*   H = HASH( V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K )
* V_C/V_S are the identification strings without CR/LF; every field
* except the shared secret K is encoded as an SSH "string", K as an
* "mpint".
    DATA lo_stream TYPE REF TO zcl_oassh_stream.

    CREATE OBJECT lo_stream.
    lo_stream->string_encode( iv_v_c ).
    lo_stream->string_encode( iv_v_s ).
    lo_stream->string_encode( iv_i_c ).
    lo_stream->string_encode( iv_i_s ).
    lo_stream->string_encode( iv_k_s ).
    lo_stream->string_encode( iv_q_c ).
    lo_stream->string_encode( iv_q_s ).
    lo_stream->mpint_encode( iv_k ).

    rv_hash = zcl_oassh_sha256=>hash( lo_stream->get( ) ).

  ENDMETHOD.


  METHOD derive_key.
* RFC 4253 section 7.2:
*   K1 = HASH( K || H || X || session_id )
*   K2 = HASH( K || H || K1 )
*   K3 = HASH( K || H || K1 || K2 )
*   ...
*   key = K1 || K2 || K3 || ...   truncated to the required length.
* K is encoded as an mpint, X is the single letter byte "A".."F".
    DATA lo_stream  TYPE REF TO zcl_oassh_stream.
    DATA lv_k       TYPE xstring.
    DATA lv_prefix  TYPE xstring.
    DATA lv_letter  TYPE xstring.
    DATA lv_input   TYPE xstring.
    DATA lv_block   TYPE xstring.

* K || H is common to every block; precompute it once
    CREATE OBJECT lo_stream.
    lo_stream->mpint_encode( iv_k ).
    lv_k = lo_stream->get( ).
    CONCATENATE lv_k iv_h INTO lv_prefix IN BYTE MODE.

    lv_letter = zcl_oassh_ascii=>to_xstring( CONV string( iv_letter ) ).
    CONCATENATE lv_prefix lv_letter iv_session_id INTO lv_input IN BYTE MODE.
    lv_block = zcl_oassh_sha256=>hash( lv_input ).
    rv_key = lv_block.

    WHILE xstrlen( rv_key ) < iv_length.
      CONCATENATE lv_prefix rv_key INTO lv_input IN BYTE MODE.
      lv_block = zcl_oassh_sha256=>hash( lv_input ).
      CONCATENATE rv_key lv_block INTO rv_key IN BYTE MODE.
    ENDWHILE.

    rv_key = rv_key(iv_length).

  ENDMETHOD.
ENDCLASS.
