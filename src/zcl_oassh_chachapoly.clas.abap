CLASS zcl_oassh_chachapoly DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
* OpenSSH PROTOCOL.chacha20poly1305: independent main/header keys,
* encrypted packet length, Poly1305 over ciphertext, and a sequence nonce.
    METHODS constructor
      IMPORTING iv_key TYPE xstring.
    METHODS encode
      IMPORTING
        iv_sequence TYPE i
        iv_plain    TYPE xstring
      RETURNING VALUE(rv_wire) TYPE xstring.
    METHODS decode_length
      IMPORTING
        iv_sequence TYPE i
        iv_header   TYPE xstring
      RETURNING VALUE(rv_length) TYPE i
      RAISING zcx_oassh_error.
    METHODS decode
      IMPORTING
        iv_sequence   TYPE i
        iv_ciphertext TYPE xstring
        iv_tag        TYPE xstring
      RETURNING VALUE(rv_plain) TYPE xstring
      RAISING zcx_oassh_error.
  PRIVATE SECTION.
    DATA mv_main_key TYPE xstring.
    DATA mv_header_key TYPE xstring.
    METHODS nonce
      IMPORTING iv_sequence TYPE i
      RETURNING VALUE(rv_nonce) TYPE xstring.
    METHODS tag
      IMPORTING
        iv_nonce      TYPE xstring
        iv_ciphertext TYPE xstring
      RETURNING VALUE(rv_tag) TYPE xstring.
    METHODS tag_matches
      IMPORTING
        iv_actual   TYPE xstring
        iv_expected TYPE xstring
      RETURNING VALUE(rv_matches) TYPE abap_bool.
ENDCLASS.


CLASS zcl_oassh_chachapoly IMPLEMENTATION.
  METHOD constructor.
    ASSERT xstrlen( iv_key ) = 64.
    mv_main_key = iv_key(32).
    mv_header_key = iv_key+32(32).
  ENDMETHOD.


  METHOD nonce.
    DATA lv_zero TYPE xstring VALUE '00000000'.
    DATA lv_sequence TYPE xstring.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    lo_stream = NEW #( ).
    lo_stream->uint32_encode( iv_sequence ).
    lv_sequence = lo_stream->get( ).
    CONCATENATE lv_zero lv_sequence INTO rv_nonce IN BYTE MODE.
  ENDMETHOD.


  METHOD tag.
    DATA lv_zeros TYPE xstring VALUE
      '0000000000000000000000000000000000000000000000000000000000000000'.
    DATA lv_poly_key TYPE xstring.
    lv_poly_key = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_main_key
      iv_nonce   = iv_nonce
      iv_counter = 0
      iv_data    = lv_zeros ).
    rv_tag = zcl_oassh_poly1305=>auth(
      iv_key  = lv_poly_key
      iv_data = iv_ciphertext ).
  ENDMETHOD.


  METHOD tag_matches.
* Accumulate every byte difference so tag verification does not reveal the
* first mismatching position.
    DATA lv_offset TYPE i.
    DATA lv_actual TYPE x LENGTH 1.
    DATA lv_expected TYPE x LENGTH 1.
    DATA lv_difference TYPE x LENGTH 1.
    IF xstrlen( iv_actual ) <> 16 OR xstrlen( iv_expected ) <> 16.
      RETURN.
    ENDIF.
    DO 16 TIMES.
      lv_offset = sy-index - 1.
      lv_actual = iv_actual+lv_offset(1).
      lv_expected = iv_expected+lv_offset(1).
      lv_difference = lv_difference BIT-OR ( lv_actual BIT-XOR lv_expected ).
    ENDDO.
    rv_matches = xsdbool( lv_difference = '00' ).
  ENDMETHOD.


  METHOD encode.
    DATA lv_nonce TYPE xstring.
    DATA lv_header TYPE xstring.
    DATA lv_body TYPE xstring.
    DATA lv_header_plain TYPE xstring.
    DATA lv_body_plain TYPE xstring.
    DATA lv_ciphertext TYPE xstring.
    DATA lv_tag TYPE xstring.
    ASSERT xstrlen( iv_plain ) >= 4.
    lv_nonce = nonce( iv_sequence ).
    lv_header_plain = iv_plain(4).
    lv_body_plain = iv_plain+4.
    lv_header = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_header_key
      iv_nonce   = lv_nonce
      iv_counter = 0
      iv_data    = lv_header_plain ).
    lv_body = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_main_key
      iv_nonce   = lv_nonce
      iv_counter = 1
      iv_data    = lv_body_plain ).
    CONCATENATE lv_header lv_body INTO lv_ciphertext IN BYTE MODE.
    lv_tag = tag(
      iv_nonce      = lv_nonce
      iv_ciphertext = lv_ciphertext ).
    CONCATENATE lv_ciphertext lv_tag INTO rv_wire IN BYTE MODE.
  ENDMETHOD.


  METHOD decode_length.
    DATA lv_nonce TYPE xstring.
    DATA lv_plain TYPE xstring.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    IF xstrlen( iv_header ) <> 4.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_nonce = nonce( iv_sequence ).
    lv_plain = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_header_key
      iv_nonce   = lv_nonce
      iv_counter = 0
      iv_data    = iv_header ).
    lo_stream = NEW #( lv_plain ).
    rv_length = lo_stream->uint32_decode( ).
  ENDMETHOD.


  METHOD decode.
    DATA lv_nonce TYPE xstring.
    DATA lv_expected_tag TYPE xstring.
    DATA lv_header TYPE xstring.
    DATA lv_body TYPE xstring.
    DATA lv_header_cipher TYPE xstring.
    DATA lv_body_cipher TYPE xstring.
    IF xstrlen( iv_ciphertext ) < 4.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-malformed_packet ).
    ENDIF.
    lv_nonce = nonce( iv_sequence ).
    lv_expected_tag = tag(
      iv_nonce      = lv_nonce
      iv_ciphertext = iv_ciphertext ).
    IF tag_matches(
        iv_actual   = iv_tag
        iv_expected = lv_expected_tag ) = abap_false.
      zcx_oassh_error=>raise( zcx_oassh_error=>c_reason-mac_invalid ).
    ENDIF.
    lv_header_cipher = iv_ciphertext(4).
    lv_body_cipher = iv_ciphertext+4.
    lv_header = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_header_key
      iv_nonce   = lv_nonce
      iv_counter = 0
      iv_data    = lv_header_cipher ).
    lv_body = zcl_oassh_chacha20=>crypt_ssh(
      iv_key     = mv_main_key
      iv_nonce   = lv_nonce
      iv_counter = 1
      iv_data    = lv_body_cipher ).
    CONCATENATE lv_header lv_body INTO rv_plain IN BYTE MODE.
  ENDMETHOD.
ENDCLASS.
