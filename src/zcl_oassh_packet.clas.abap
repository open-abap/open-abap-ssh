CLASS zcl_oassh_packet DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* RFC 4254 sections 5.1 and 5.2: the advertised 32768-byte channel data
* maximum must fit both DATA (9-byte envelope) and EXTENDED_DATA (13 bytes).
    CONSTANTS c_max_payload_length TYPE i VALUE 32781.
    CONSTANTS c_max_packet_length TYPE i VALUE 35000.
    CONSTANTS c_cipher_aes128_ctr TYPE string VALUE 'aes128-ctr'.
    CONSTANTS c_cipher_chachapoly TYPE string VALUE 'chacha20-poly1305@openssh.com'.
    METHODS constructor
      IMPORTING
        ii_random            TYPE REF TO zif_oassh_random
        iv_encrypt_key       TYPE xstring OPTIONAL
        iv_encrypt_iv        TYPE xstring OPTIONAL
        iv_encrypt_mac       TYPE xstring OPTIONAL
        iv_encrypt_algorithm TYPE string DEFAULT c_cipher_aes128_ctr
        iv_decrypt_key       TYPE xstring OPTIONAL
        iv_decrypt_iv        TYPE xstring OPTIONAL
        iv_decrypt_mac       TYPE xstring OPTIONAL
        iv_decrypt_algorithm TYPE string DEFAULT c_cipher_aes128_ctr
        iv_send_sequence     TYPE i OPTIONAL
        iv_receive_sequence  TYPE i OPTIONAL.
    METHODS encode
      IMPORTING
        iv_payload       TYPE xstring
      RETURNING
        VALUE(rv_packet) TYPE xstring
      RAISING
        zcx_oassh_error.
    METHODS decode
      IMPORTING
        iv_packet         TYPE xstring
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
        iv_encrypt_key       TYPE xstring OPTIONAL
        iv_encrypt_iv        TYPE xstring OPTIONAL
        iv_encrypt_mac       TYPE xstring OPTIONAL
        iv_encrypt_algorithm TYPE string DEFAULT c_cipher_aes128_ctr.
    METHODS rekey_decrypt
      IMPORTING
        iv_decrypt_key       TYPE xstring OPTIONAL
        iv_decrypt_iv        TYPE xstring OPTIONAL
        iv_decrypt_mac       TYPE xstring OPTIONAL
        iv_decrypt_algorithm TYPE string DEFAULT c_cipher_aes128_ctr.
    METHODS reset_send_sequence.
    METHODS reset_receive_sequence.
    METHODS get_send_sequence
      RETURNING
        VALUE(rv_sequence) TYPE i.
    METHODS get_receive_sequence
      RETURNING
        VALUE(rv_sequence) TYPE i.
    METHODS get_last_receive_sequence
      RETURNING
        VALUE(rv_sequence) TYPE i.
    METHODS get_auth_length
      RETURNING VALUE(rv_length) TYPE i.
    METHODS get_header_length
      RETURNING VALUE(rv_length) TYPE i.
    METHODS clear_secrets.

  PRIVATE SECTION.
    DATA mi_random TYPE REF TO zif_oassh_random.
    DATA mo_encrypt TYPE REF TO zcl_oassh_ctr.
    DATA mo_decrypt TYPE REF TO zcl_oassh_ctr.
    DATA mo_encrypt_chachapoly TYPE REF TO zcl_oassh_chachapoly.
    DATA mo_decrypt_chachapoly TYPE REF TO zcl_oassh_chachapoly.
    DATA mv_encrypt_mac TYPE xstring.
    DATA mv_decrypt_mac TYPE xstring.
    DATA mv_send_sequence TYPE i.
    DATA mv_receive_sequence TYPE i.
    DATA mv_recv_plain TYPE xstring.
    DATA mv_recv_cipher TYPE xstring.

    METHODS mac
      IMPORTING
        iv_key        TYPE xstring
        iv_sequence   TYPE i
        iv_plain      TYPE xstring
      RETURNING
        VALUE(rv_mac) TYPE xstring.
    CLASS-METHODS auth_matches
      IMPORTING
        iv_actual         TYPE xstring
        iv_expected       TYPE xstring
      RETURNING
        VALUE(rv_matches) TYPE abap_bool.
    METHODS validate_packet_length
      IMPORTING
        iv_length   TYPE i
        iv_expected TYPE i DEFAULT -1
      RAISING zcx_oassh_error.
    CLASS-METHODS next_sequence
      IMPORTING
        iv_sequence        TYPE i
      RETURNING
        VALUE(rv_sequence) TYPE i.
    METHODS clear_encrypt_secrets.
    METHODS clear_decrypt_secrets.
ENDCLASS.


CLASS zcl_oassh_packet IMPLEMENTATION.

  METHOD clear_encrypt_secrets.
    IF mo_encrypt IS BOUND.
      mo_encrypt->clear_secrets( ).
    ENDIF.
    IF mo_encrypt_chachapoly IS BOUND.
      mo_encrypt_chachapoly->clear_secrets( ).
    ENDIF.
    CLEAR mo_encrypt.
    CLEAR mo_encrypt_chachapoly.
    CLEAR mv_encrypt_mac.
  ENDMETHOD.


  METHOD clear_decrypt_secrets.
    IF mo_decrypt IS BOUND.
      mo_decrypt->clear_secrets( ).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      mo_decrypt_chachapoly->clear_secrets( ).
    ENDIF.
    CLEAR mo_decrypt.
    CLEAR mo_decrypt_chachapoly.
    CLEAR mv_decrypt_mac.
    CLEAR mv_recv_plain.
    CLEAR mv_recv_cipher.
  ENDMETHOD.


  METHOD clear_secrets.
    clear_encrypt_secrets( ).
    clear_decrypt_secrets( ).
  ENDMETHOD.

  METHOD constructor.
    mi_random = ii_random.
    mv_send_sequence = iv_send_sequence.
    mv_receive_sequence = iv_receive_sequence.
    rekey_encrypt(
      iv_encrypt_key       = iv_encrypt_key
      iv_encrypt_iv        = iv_encrypt_iv
      iv_encrypt_mac       = iv_encrypt_mac
      iv_encrypt_algorithm = iv_encrypt_algorithm ).
    rekey_decrypt(
      iv_decrypt_key       = iv_decrypt_key
      iv_decrypt_iv        = iv_decrypt_iv
      iv_decrypt_mac       = iv_decrypt_mac
      iv_decrypt_algorithm = iv_decrypt_algorithm ).
  ENDMETHOD.


  METHOD rekey_encrypt.
* RFC 4253 section 9: replacing algorithms does not reset packet sequence
* numbers. The outbound cipher changes after our NEWKEYS has been sent.
    clear_encrypt_secrets( ).
    mv_encrypt_mac = iv_encrypt_mac.
    IF iv_encrypt_key IS NOT INITIAL.
      CASE iv_encrypt_algorithm.
        WHEN c_cipher_aes128_ctr.
          ASSERT xstrlen( iv_encrypt_iv ) = 16.
          mo_encrypt = NEW #(
            iv_key     = iv_encrypt_key
            iv_counter = iv_encrypt_iv ).
        WHEN c_cipher_chachapoly.
          ASSERT xstrlen( iv_encrypt_key ) = 64.
          ASSERT iv_encrypt_iv IS INITIAL.
          ASSERT iv_encrypt_mac IS INITIAL.
          mo_encrypt_chachapoly = NEW #( iv_encrypt_key ).
        WHEN OTHERS.
          ASSERT 1 = 2.
      ENDCASE.
    ENDIF.
  ENDMETHOD.


  METHOD rekey_decrypt.
* The inbound cipher changes only after the peer's NEWKEYS has been received.
    clear_decrypt_secrets( ).
    mv_decrypt_mac = iv_decrypt_mac.
    IF iv_decrypt_key IS NOT INITIAL.
      CASE iv_decrypt_algorithm.
        WHEN c_cipher_aes128_ctr.
          ASSERT xstrlen( iv_decrypt_iv ) = 16.
          mo_decrypt = NEW #(
            iv_key     = iv_decrypt_key
            iv_counter = iv_decrypt_iv ).
        WHEN c_cipher_chachapoly.
          ASSERT xstrlen( iv_decrypt_key ) = 64.
          ASSERT iv_decrypt_iv IS INITIAL.
          ASSERT iv_decrypt_mac IS INITIAL.
          mo_decrypt_chachapoly = NEW #( iv_decrypt_key ).
        WHEN OTHERS.
          ASSERT 1 = 2.
      ENDCASE.
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


  METHOD get_last_receive_sequence.
* decode increments after every accepted packet; invert that step while
* preserving uint32 rollover in ABAP's signed representation.
    DATA lv_min_i TYPE i.
    lv_min_i = -2147483647 - 1.
    IF mv_receive_sequence = lv_min_i.
      rv_sequence = 2147483647.
    ELSE.
      rv_sequence = mv_receive_sequence - 1.
    ENDIF.
  ENDMETHOD.


  METHOD get_auth_length.
    IF mo_decrypt_chachapoly IS BOUND.
      rv_length = 16.
    ELSEIF mv_decrypt_mac IS NOT INITIAL.
      rv_length = 32.
    ENDIF.
  ENDMETHOD.


  METHOD get_header_length.
    IF mo_decrypt_chachapoly IS BOUND.
      rv_length = 4.
    ELSE.
      rv_length = 16.
    ENDIF.
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


  METHOD auth_matches.
* Accumulate all byte differences so HMAC rejection does not disclose the
* first mismatching position. Length is checked before any byte access.
    DATA lv_offset TYPE i.
    DATA lv_actual TYPE x LENGTH 1.
    DATA lv_expected TYPE x LENGTH 1.
    DATA lv_difference TYPE x LENGTH 1.
    IF xstrlen( iv_actual ) <> xstrlen( iv_expected ).
      RETURN.
    ENDIF.
    DO xstrlen( iv_actual ) TIMES.
      lv_offset = sy-index - 1.
      lv_actual = iv_actual+lv_offset(1).
      lv_expected = iv_expected+lv_offset(1).
      lv_difference = lv_difference BIT-OR ( lv_actual BIT-XOR lv_expected ).
    ENDDO.
    rv_matches = xsdbool( lv_difference = '00' ).
  ENDMETHOD.


  METHOD next_sequence.
* RFC 4253 section 6.4: the packet sequence number is an unsigned uint32 and
* wraps modulo 2^32. ABAP type i is signed, so cross its positive boundary
* explicitly instead of triggering an arithmetic overflow.
    IF iv_sequence = 2147483647.
      rv_sequence = -2147483647 - 1.
    ELSE.
      rv_sequence = iv_sequence + 1.
    ENDIF.
  ENDMETHOD.


  METHOD validate_packet_length.
    IF iv_expected >= 0 AND iv_length <> iv_expected.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND AND iv_length < 5.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ELSEIF mo_decrypt_chachapoly IS NOT BOUND AND iv_length < 12.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
  ENDMETHOD.


  METHOD encode.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_block_size TYPE i VALUE 8.
    DATA lv_padding_length TYPE i.
    DATA lv_packet_length TYPE i.
    DATA lv_alignment_length TYPE i.
    DATA lv_padding_byte TYPE x LENGTH 1.
    DATA lv_plain TYPE xstring.
    DATA lv_mac TYPE xstring.

    IF xstrlen( iv_payload ) > c_max_payload_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    IF mo_encrypt IS BOUND.
      lv_block_size = 16.
    ENDIF.
    lv_alignment_length = xstrlen( iv_payload ) + 5.
    IF mo_encrypt_chachapoly IS BOUND.
* OpenSSH AEAD treats the encrypted length as four bytes of AAD, so only
* padding_length + payload + padding must align to the cipher block size.
      lv_alignment_length = lv_alignment_length - 4.
    ENDIF.
    lv_padding_length = lv_block_size - ( lv_alignment_length MOD lv_block_size ).
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
    IF mo_encrypt_chachapoly IS BOUND.
      rv_packet = mo_encrypt_chachapoly->encode(
        iv_sequence = mv_send_sequence
        iv_plain    = lv_plain ).
    ELSEIF mo_encrypt IS BOUND.
      rv_packet = mo_encrypt->crypt( lv_plain ).
    ELSE.
      rv_packet = lv_plain.
    ENDIF.
    IF mo_encrypt_chachapoly IS NOT BOUND.
      CONCATENATE rv_packet lv_mac INTO rv_packet IN BYTE MODE.
    ENDIF.
    IF xstrlen( rv_packet ) > c_max_packet_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    mv_send_sequence = next_sequence( mv_send_sequence ).
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
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
* Four-byte encrypted length, one aligned eight-byte packet body, and tag.
      IF lv_cipher_length < 28.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_cipher_length = lv_cipher_length - 16.
      lv_received_mac = iv_packet+lv_cipher_length(16).
    ELSEIF mv_decrypt_mac IS NOT INITIAL.
      IF lv_cipher_length < 32.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_cipher_length = lv_cipher_length - 32.
      lv_received_mac = iv_packet+lv_cipher_length(32).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      IF lv_cipher_length < 12.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
    ELSEIF lv_cipher_length < 16.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      IF ( lv_cipher_length - 4 ) MOD 8 <> 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_cipher = iv_packet(lv_cipher_length).
      lv_plain = mo_decrypt_chachapoly->decode(
        iv_sequence   = mv_receive_sequence
        iv_ciphertext = lv_cipher
        iv_tag        = lv_received_mac ).
    ELSEIF mo_decrypt IS BOUND.
      IF lv_cipher_length MOD 16 <> 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_cipher = iv_packet(lv_cipher_length).
      lv_plain = mo_decrypt->crypt( lv_cipher ).
    ELSE.
      IF lv_cipher_length MOD 8 <> 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_plain = iv_packet(lv_cipher_length).
    ENDIF.

    IF mv_decrypt_mac IS NOT INITIAL.
      lv_expected_mac = mac(
        iv_key      = mv_decrypt_mac
        iv_sequence = mv_receive_sequence
        iv_plain    = lv_plain ).
      IF auth_matches(
          iv_actual   = lv_received_mac
          iv_expected = lv_expected_mac ) = abap_false.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e004(zoassh).
      ENDIF.
    ENDIF.

    lo_stream = NEW #( lv_plain ).
    lv_packet_length = lo_stream->uint32_decode( ).
    lv_expected_packet_length = lv_cipher_length - 4.
    validate_packet_length(
      iv_length   = lv_packet_length
      iv_expected = lv_expected_packet_length ).
    lv_padding_length = lo_stream->byte_decode( ).
    IF lv_padding_length < 4 OR lv_padding_length >= lv_packet_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    lv_payload_length = lv_packet_length - lv_padding_length - 1.
    IF lv_payload_length > c_max_payload_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    rv_payload = lo_stream->take( lv_payload_length ).
    ASSERT lo_stream->get_length( ) = lv_padding_length.
    mv_receive_sequence = next_sequence( mv_receive_sequence ).
  ENDMETHOD.


  METHOD decode_length.
* Decrypt the first cipher block so the (encrypted) packet_length field can be
* read; the CTR keystream is streaming, so the plaintext is buffered here and
* consumed by decode_remainder. Used to frame packets on a byte stream.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA lv_mac_length TYPE i.
    DATA lv_max_packet_length TYPE i.
    IF xstrlen( iv_first_block ) <> get_header_length( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      mv_recv_cipher = iv_first_block.
      rv_packet_length = mo_decrypt_chachapoly->decode_length(
        iv_sequence = mv_receive_sequence
        iv_header   = iv_first_block ).
    ELSEIF mo_decrypt IS BOUND.
      mv_recv_plain = mo_decrypt->crypt( iv_first_block ).
    ELSE.
      mv_recv_plain = iv_first_block.
    ENDIF.
    IF mo_decrypt_chachapoly IS NOT BOUND.
      lo_stream = NEW #( mv_recv_plain ).
      rv_packet_length = lo_stream->uint32_decode_peek( ).
    ENDIF.
    lv_mac_length = get_auth_length( ).
    lv_max_packet_length = c_max_packet_length - 4 - lv_mac_length.
    validate_packet_length( rv_packet_length ).
    IF rv_packet_length > lv_max_packet_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
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
    DATA lv_buffered_length TYPE i.
    IF get_auth_length( ) = 0 AND iv_mac IS NOT INITIAL.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF get_auth_length( ) > 0 AND xstrlen( iv_mac ) <> get_auth_length( ).
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      lv_buffered_length = xstrlen( mv_recv_cipher ).
    ELSE.
      lv_buffered_length = xstrlen( mv_recv_plain ).
    ENDIF.
    IF lv_buffered_length + xstrlen( iv_rest ) + xstrlen( iv_mac ) > c_max_packet_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    IF mo_decrypt_chachapoly IS BOUND.
      CONCATENATE mv_recv_cipher iv_rest INTO mv_recv_cipher IN BYTE MODE.
      IF ( xstrlen( mv_recv_cipher ) - 4 ) MOD 8 <> 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      mv_recv_plain = mo_decrypt_chachapoly->decode(
        iv_sequence   = mv_receive_sequence
        iv_ciphertext = mv_recv_cipher
        iv_tag        = iv_mac ).
      CLEAR mv_recv_cipher.
    ELSEIF mo_decrypt IS BOUND.
      IF xstrlen( iv_rest ) MOD 16 <> 0.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
      ENDIF.
      lv_rest_plain = mo_decrypt->crypt( iv_rest ).
    ELSE.
      lv_rest_plain = iv_rest.
    ENDIF.
    IF mo_decrypt_chachapoly IS NOT BOUND.
      CONCATENATE mv_recv_plain lv_rest_plain INTO mv_recv_plain IN BYTE MODE.
    ENDIF.

    IF mv_decrypt_mac IS NOT INITIAL.
      lv_expected_mac = mac(
        iv_key      = mv_decrypt_mac
        iv_sequence = mv_receive_sequence
        iv_plain    = mv_recv_plain ).
      IF auth_matches(
          iv_actual   = iv_mac
          iv_expected = lv_expected_mac ) = abap_false.
        RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e004(zoassh).
      ENDIF.
    ENDIF.

    lo_stream = NEW #( mv_recv_plain ).
    lv_packet_length = lo_stream->uint32_decode( ).
    lv_expected_packet_length = xstrlen( mv_recv_plain ) - 4.
    validate_packet_length(
      iv_length   = lv_packet_length
      iv_expected = lv_expected_packet_length ).
    lv_padding_length = lo_stream->byte_decode( ).
    IF lv_padding_length < 4 OR lv_padding_length >= lv_packet_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    lv_payload_length = lv_packet_length - lv_padding_length - 1.
    IF lv_payload_length > c_max_payload_length.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e002(zoassh).
    ENDIF.
    rv_payload = lo_stream->take( lv_payload_length ).
    ASSERT lo_stream->get_length( ) = lv_padding_length.
    mv_receive_sequence = next_sequence( mv_receive_sequence ).
    CLEAR mv_recv_plain.
  ENDMETHOD.
ENDCLASS.
