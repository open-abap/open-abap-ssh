CLASS zcl_oassh_message_50 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* SSH_MSG_USERAUTH_REQUEST for password and signed publickey methods.
    TYPES:
      BEGIN OF ty_data,
        message_id   TYPE x LENGTH 1,
        user_name    TYPE xstring,
        service_name TYPE xstring,
        method_name  TYPE xstring,
        password     TYPE xstring,
      END OF ty_data.
    TYPES:
      BEGIN OF ty_publickey,
        message_id   TYPE x LENGTH 1,
        user_name    TYPE xstring,
        service_name TYPE xstring,
        method_name  TYPE xstring,
        algorithm    TYPE xstring,
        public_key   TYPE xstring,
        signature    TYPE xstring,
      END OF ty_publickey.

    CONSTANTS gc_message_id TYPE x LENGTH 1 VALUE '32'. " is 50 in decimal

    CLASS-METHODS parse
      IMPORTING
        io_stream      TYPE REF TO zcl_oassh_stream
      RETURNING
        VALUE(rs_data) TYPE ty_data
      RAISING zcx_oassh_error.

    CLASS-METHODS serialize
      IMPORTING
        is_data          TYPE ty_data
      RETURNING
        VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
    CLASS-METHODS serialize_publickey_unsigned
      IMPORTING is_data          TYPE ty_publickey
      RETURNING VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
    CLASS-METHODS serialize_publickey
      IMPORTING is_data          TYPE ty_publickey
      RETURNING VALUE(ro_stream) TYPE REF TO zcl_oassh_stream.
    CLASS-METHODS signed_publickey_request
      IMPORTING
        iv_user                   TYPE xstring
        iv_session_id             TYPE xstring
        iv_private_seed           TYPE xstring
      RETURNING VALUE(rv_payload) TYPE xstring.

  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS zcl_oassh_message_50 IMPLEMENTATION.


  METHOD parse.
* https://datatracker.ietf.org/doc/html/rfc4252#section-8
* SSH_MSG_USERAUTH_REQUEST, password method
    DATA lv_password_method TYPE xstring.

    rs_data-message_id = io_stream->take( 1 ).
    IF rs_data-message_id <> gc_message_id.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    rs_data-user_name = io_stream->string_decode( ).
    rs_data-service_name = io_stream->string_decode( ).
    rs_data-method_name = io_stream->string_decode( ).
    lv_password_method = zcl_oassh_ascii=>to_xstring( 'password' ).
    IF rs_data-method_name <> lv_password_method.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
* the boolean FALSE means "this is not a password change request"
    IF io_stream->boolean_decode( ) <> abap_false.
      RAISE EXCEPTION TYPE zcx_oassh_error MESSAGE e003(zoassh).
    ENDIF.
    rs_data-password = io_stream->string_decode( ).

  ENDMETHOD.


  METHOD serialize.

    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-user_name ).
    ro_stream->string_encode( is_data-service_name ).
    ro_stream->string_encode( is_data-method_name ).
    ro_stream->boolean_encode( abap_false ).
    ro_stream->string_encode( is_data-password ).

  ENDMETHOD.


  METHOD serialize_publickey_unsigned.
* RFC 4252 section 7: this exact prefix is also the signed request data.
    ro_stream = NEW #( ).
    ro_stream->append( gc_message_id ).
    ro_stream->string_encode( is_data-user_name ).
    ro_stream->string_encode( is_data-service_name ).
    ro_stream->string_encode( is_data-method_name ).
    ro_stream->boolean_encode( abap_true ).
    ro_stream->string_encode( is_data-algorithm ).
    ro_stream->string_encode( is_data-public_key ).
  ENDMETHOD.


  METHOD serialize_publickey.
    ro_stream = serialize_publickey_unsigned( is_data ).
    ro_stream->string_encode( is_data-signature ).
  ENDMETHOD.


  METHOD signed_publickey_request.
    DATA ls_request TYPE ty_publickey.
    DATA lo_key TYPE REF TO zcl_oassh_stream.
    DATA lo_signature TYPE REF TO zcl_oassh_stream.
    DATA lo_signed TYPE REF TO zcl_oassh_stream.
    DATA lv_unsigned TYPE xstring.
    DATA lv_public TYPE xstring.
    DATA lv_signature TYPE xstring.
    ls_request-message_id = gc_message_id.
    ls_request-user_name = iv_user.
    ls_request-service_name = zcl_oassh_ascii=>to_xstring( 'ssh-connection' ).
    ls_request-method_name = zcl_oassh_ascii=>to_xstring( 'publickey' ).
    ls_request-algorithm = zcl_oassh_ascii=>to_xstring( 'ssh-ed25519' ).
    lv_public = zcl_oassh_ed25519=>public_key( iv_private_seed ).
    lo_key = NEW #( ).
    lo_key->string_encode( ls_request-algorithm ).
    lo_key->string_encode( lv_public ).
    ls_request-public_key = lo_key->get( ).
    lv_unsigned = serialize_publickey_unsigned( ls_request )->get( ).
    lo_signed = NEW #( ).
    lo_signed->string_encode( iv_session_id ).
    lo_signed->append( lv_unsigned ).
    lv_signature = zcl_oassh_ed25519=>sign_message(
      iv_seed    = iv_private_seed
      iv_message = lo_signed->get( ) ).
    lo_signature = NEW #( ).
    lo_signature->string_encode( ls_request-algorithm ).
    lo_signature->string_encode( lv_signature ).
    ls_request-signature = lo_signature->get( ).
    rv_payload = serialize_publickey( ls_request )->get( ).
  ENDMETHOD.
ENDCLASS.
