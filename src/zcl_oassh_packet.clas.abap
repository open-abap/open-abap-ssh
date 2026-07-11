CLASS zcl_oassh_packet DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    CONSTANTS c_max_payload_length TYPE i VALUE 32768.
    CONSTANTS c_max_packet_length TYPE i VALUE 35000.
    METHODS constructor
      IMPORTING
        ii_random      TYPE REF TO zif_oassh_random
        iv_encrypt_key TYPE xstring OPTIONAL
        iv_encrypt_iv  TYPE xstring OPTIONAL
        iv_encrypt_mac TYPE xstring OPTIONAL
        iv_decrypt_key TYPE xstring OPTIONAL
        iv_decrypt_iv  TYPE xstring OPTIONAL
        iv_decrypt_mac TYPE xstring OPTIONAL
        iv_send_sequence TYPE i OPTIONAL
        iv_receive_sequence TYPE i OPTIONAL.
    METHODS encode
      IMPORTING
        iv_payload       TYPE xstring
      RETURNING
        VALUE(rv_packet) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS decode
      IMPORTING
        iv_packet        TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS decode_length
      IMPORTING
        iv_first_block          TYPE xstring
      RETURNING
        VALUE(rv_packet_length) TYPE i
      RAISING
        zcx_oassh_error.
    METHODS decode_remainder
      IMPORTING
        iv_rest           TYPE xstring
        iv_mac            TYPE xstring
      RETURNING
        VALUE(rv_payload) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS rekey_encrypt
      IMPORTING
        iv_encrypt_key TYPE xstring OPTIONAL
        iv_encrypt_iv  TYPE xstring OPTIONAL
        iv_encrypt_mac TYPE xstring OPTIONAL.
    METHODS rekey_decrypt
      IMPORTING
        iv_decrypt_key TYPE xstring OPTIONAL
        iv_decrypt_iv  TYPE xstring OPTIONAL
        iv_decrypt_mac TYPE xstring OPTIONAL.
    METHODS reset_send_sequence.
    METHODS reset_receive_sequence.
    METHODS get_send_sequence
      RETURNING
        VALUE(rv_sequence) TYPE i.
    METHODS get_receive_sequence
      RETURNING
        VALUE(rv_sequence) TYPE i.

  PRIVATE SECTION.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mo_encrypt TYPE REF TO zcl_oassh_ctr.
    DATA mo_decrypt TYPE REF TO zcl_oassh_ctr.
    DATA mv_encrypt_mac TYPE xstring.
    DATA mv_decrypt_mac TYPE xstring.
    DATA mv_send_sequence TYPE i.
    DATA mv_receive_sequence TYPE i.
    DATA mv_recv_plain TYPE xstring.

    METHODS mac
      IMPORTING
        iv_key        TYPE xstring
        iv_sequence   TYPE i
        iv_plain      TYPE xstring
      RETURNING
        VALUE(rv_mac) TYPE xstring.
ENDCLASS.


CLASS zcl_oassh_packet IMPLEMENTATION.

  METHOD constructor.
    mi_random = ii_random.
    mv_send_sequence = iv_send_sequence.
    mv_receive_sequence = iv_receive_sequence.
    rekey_encrypt(
      iv_encrypt_key = iv_encrypt_key
      iv_encrypt_iv  = iv_encrypt_iv
      iv_encrypt_mac = iv_encrypt_mac ).
    rekey_decrypt(
      iv_decrypt_key = iv_decrypt_key
      iv_decrypt_iv  = iv_decrypt_iv
      iv_decrypt_mac = iv_decrypt_mac ).
  ENDMETHOD.


  METHOD rekey_encrypt.
* RFC 4253 section 9: replacing algorithms does not reset packet sequence
* numbers. The outbound cipher changes after our NEWKEYS has been sent.
    CLEAR mo_encrypt.
    mv_encrypt_mac = iv_encrypt_mac.
    IF iv_encrypt_key IS NOT INITIAL.
      ASSERT xstrlen( iv_encrypt_iv ) = 16.
      mo_encrypt = NEW #(
        iv_key     = iv_encrypt_key
        iv_counter = iv_encrypt_iv ).
    ENDIF.
  ENDMETHOD.


  METHOD rekey_decrypt.
* The inbound cipher changes only after the peer's NEWKEYS has been received.
    CLEAR mo_decrypt.
    mv_decrypt_mac = iv_decrypt_mac.
    IF iv_decrypt_key IS NOT INITIAL.
      ASSERT xstrlen( iv_decrypt_iv ) = 16.
      mo_decrypt = NEW #(
        iv_key     = iv_decrypt_key
        iv_counter = iv_decrypt_iv ).
    ENDIF.
  ENDMETHOD.


  METHOD reset_send_sequence.
    CLEAR mv_send_sequence.
  ENDMETHOD.


  METHOD reset_receive_sequence.
    CLEAR mv_receive_sequence.
  ENDMETHOD.


  METHOD get_send_sequence.
    rv_sequence = mv_send_sequence.
  ENDMETHOD.


  METHOD get_receive_sequence.
    rv_sequence = mv_receive_sequence.
  ENDMETHOD.


  METHOD mac.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->uint32_encode( iv_sequence ).
    lo_stream->append( iv_plain ).
    rv_mac = zcl_oassh_hmac=>sha256(
      iv_key  = iv_key
      iv_data = lo_stream->get( ) ).
  ENDMETHOD.


  METHOD encode.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_block_size TYPE i VALUE 8.
    DATA lv_padding_length TYPE i.
    DATA lv_packet_length TYPE i.
    DATA lv_padding_byte TYPE x LENGTH 1.
    DATA lv_plain TYPE xstring.
    DATA lv_mac TYPE xstring.

    IF xstrlen( iv_payload ) > c_max_payload_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    IF mo_encrypt IS BOUND.
      lv_block_size = 16.
    ENDIF.
    lv_padding_length = lv_block_size - ( ( xstrlen( iv_payload ) + 5 ) MOD lv_block_size ).
    IF lv_padding_length < 4.
      lv_padding_length = lv_padding_length + lv_block_size.
    ENDIF.
    lv_packet_length = xstrlen( iv_payload ) + lv_padding_length + 1.

    lo_stream = NEW #( ).
    lo_stream->uint32_encode( lv_packet_length ).
    lv_padding_byte = lv_padding_length.
    lo_stream->byte_encode( lv_padding_byte ).
    lo_stream->append( iv_payload ).
    lo_stream->append( mi_random->bytes( lv_padding_length ) ).
    lv_plain = lo_stream->get( ).

    IF mv_encrypt_mac IS NOT INITIAL.
      lv_mac = mac(
        iv_key      = mv_encrypt_mac
        iv_sequence = mv_send_sequence
        iv_plain    = lv_plain ).
    ENDIF.
    IF mo_encrypt IS BOUND.
      rv_packet = mo_encrypt->crypt( lv_plain ).
    ELSE.
      rv_packet = lv_plain.
    ENDIF.
    CONCATENATE rv_packet lv_mac INTO rv_packet IN BYTE MODE.
    IF xstrlen( rv_packet ) > c_max_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    mv_send_sequence = mv_send_sequence + 1.
  ENDMETHOD.


  METHOD decode.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_cipher_length TYPE i.
    DATA lv_cipher TYPE xstring.
    DATA lv_plain TYPE xstring.
    DATA lv_received_mac TYPE xstring.
    DATA lv_expected_mac TYPE xstring.
    DATA lv_packet_length TYPE i.
    DATA lv_padding_length TYPE i.
    DATA lv_payload_length TYPE i.
    DATA lv_expected_packet_length TYPE i.

    lv_cipher_length = xstrlen( iv_packet ).
    IF lv_cipher_length > c_max_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    IF mv_decrypt_mac IS NOT INITIAL.
      IF lv_cipher_length < 32.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_cipher_length = lv_cipher_length - 32.
      lv_received_mac = iv_packet+lv_cipher_length(32).
    ENDIF.
    IF lv_cipher_length < 16.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF mo_decrypt IS BOUND.
      IF lv_cipher_length MOD 16 <> 0.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_cipher = iv_packet(lv_cipher_length).
      lv_plain = mo_decrypt->crypt( lv_cipher ).
    ELSE.
      IF lv_cipher_length MOD 8 <> 0.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_plain = iv_packet(lv_cipher_length).
    ENDIF.

    IF mv_decrypt_mac IS NOT INITIAL.
      lv_expected_mac = mac(
        iv_key      = mv_decrypt_mac
        iv_sequence = mv_receive_sequence
        iv_plain    = lv_plain ).
      IF lv_received_mac <> lv_expected_mac.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-mac_invalid ).
      ENDIF.
    ENDIF.

    lo_stream = NEW #( lv_plain ).
    lv_packet_length = lo_stream->uint32_decode( ).
    lv_expected_packet_length = lv_cipher_length - 4.
    IF lv_packet_length < 12 OR lv_packet_length <> lv_expected_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_padding_length = lo_stream->byte_decode( ).
    IF lv_padding_length < 4 OR lv_padding_length >= lv_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_payload_length = lv_packet_length - lv_padding_length - 1.
    IF lv_payload_length > c_max_payload_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    rv_payload = lo_stream->take( lv_payload_length ).
    ASSERT lo_stream->get_length( ) = lv_padding_length.
    mv_receive_sequence = mv_receive_sequence + 1.
  ENDMETHOD.


  METHOD decode_length.
* Decrypt the first cipher block so the (encrypted) packet_length field can be
* read; the CTR keystream is streaming, so the plaintext is buffered here and
* consumed by decode_remainder. Used to frame packets on a byte stream.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_mac_length TYPE i.
    DATA lv_max_packet_length TYPE i.
    IF xstrlen( iv_first_block ) <> 16.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF mo_decrypt IS BOUND.
      mv_recv_plain = mo_decrypt->crypt( iv_first_block ).
    ELSE.
      mv_recv_plain = iv_first_block.
    ENDIF.
    lo_stream = NEW #( mv_recv_plain ).
    rv_packet_length = lo_stream->uint32_decode_peek( ).
    IF mv_decrypt_mac IS NOT INITIAL.
      lv_mac_length = 32.
    ENDIF.
    lv_max_packet_length = c_max_packet_length - 4 - lv_mac_length.
    IF rv_packet_length < 12.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF rv_packet_length > lv_max_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
  ENDMETHOD.


  METHOD decode_remainder.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_expected_mac TYPE xstring.
    DATA lv_rest_plain TYPE xstring.
    DATA lv_packet_length TYPE i.
    DATA lv_padding_length TYPE i.
    DATA lv_payload_length TYPE i.
    DATA lv_expected_packet_length TYPE i.
    IF mv_decrypt_mac IS INITIAL AND iv_mac IS NOT INITIAL.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF mv_decrypt_mac IS NOT INITIAL AND xstrlen( iv_mac ) <> 32.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    IF xstrlen( mv_recv_plain ) + xstrlen( iv_rest ) + xstrlen( iv_mac ) > c_max_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    IF mo_decrypt IS BOUND.
      IF xstrlen( iv_rest ) MOD 16 <> 0.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
      ENDIF.
      lv_rest_plain = mo_decrypt->crypt( iv_rest ).
    ELSE.
      lv_rest_plain = iv_rest.
    ENDIF.
    CONCATENATE mv_recv_plain lv_rest_plain INTO mv_recv_plain IN BYTE MODE.

    IF mv_decrypt_mac IS NOT INITIAL.
      lv_expected_mac = mac(
        iv_key      = mv_decrypt_mac
        iv_sequence = mv_receive_sequence
        iv_plain    = mv_recv_plain ).
      IF iv_mac <> lv_expected_mac.
        zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-mac_invalid ).
      ENDIF.
    ENDIF.

    lo_stream = NEW #( mv_recv_plain ).
    lv_packet_length = lo_stream->uint32_decode( ).
    lv_expected_packet_length = xstrlen( mv_recv_plain ) - 4.
    IF lv_packet_length < 12 OR lv_packet_length <> lv_expected_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_padding_length = lo_stream->byte_decode( ).
    IF lv_padding_length < 4 OR lv_padding_length >= lv_packet_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_payload_length = lv_packet_length - lv_padding_length - 1.
    IF lv_payload_length > c_max_payload_length.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-packet_too_large ).
    ENDIF.
    rv_payload = lo_stream->take( lv_payload_length ).
    ASSERT lo_stream->get_length( ) = lv_padding_length.
    mv_receive_sequence = mv_receive_sequence + 1.
    CLEAR mv_recv_plain.
  ENDMETHOD.
ENDCLASS.
