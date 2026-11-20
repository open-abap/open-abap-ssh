REPORT zoassh_example_git_clone LINE-SIZE 255.

* -----------------------------------------------------------------------------
* open-abap-ssh example: fetch a GitHub repository over SSH with a deploy key,
* the transport half of "git clone --depth 1 git@github.com:owner/repo.git".
*
* The report authenticates as user "git" with an Ed25519 deploy key, runs
* git-upload-pack through zif_oassh_interactive_exec, reads the advertised
* refs, requests one ref, and receives the packfile. It then checks the pack
* header and its SHA-1 trailer and shows the result on the ABAP list.
* Decoding the objects in the pack (zlib inflate, delta resolution) is
* git-specific work outside this library; hand lv_pack to a packfile decoder
* such as the one in abapGit to obtain commits, trees, and blobs.
*
* Copy this report into a system that has open-abap-ssh installed, activate it,
* and run it. The SAP system must permit outbound TCP to ssh.github.com:443
* through ABAP Push Channels (APC). Port 443 is the default because outbound
* port 22 is often blocked; set p_host = github.com and p_port = 22 where it is
* open.
*
* Creating the deploy key:
*   1. ssh-keygen -t ed25519 -N "" -C "open-abap-ssh" -f deploy_key
*   2. On GitHub: repository > Settings > Deploy keys > Add deploy key, paste
*      deploy_key.pub, leave "Allow write access" unchecked.
*   3. Print the 32-byte private seed as hex (unencrypted Ed25519 keys only):
*        sed '1d;$d' deploy_key | base64 -d | tail -c +162 | head -c 32
*          | xxd -p -c 32
*      (one command line) and enter it as p_seed.
*
* SECURITY: the seed is the deploy key. Entering it on a selection screen is
* fine for a try-out; production code should read it from the platform's
* secret store. lcl_github_host pins GitHub's published host keys, so a
* connection to anything that is not GitHub is rejected.
* -----------------------------------------------------------------------------

PARAMETERS p_repo  TYPE string LOWER CASE OBLIGATORY DEFAULT 'open-abap/open-abap-ssh.git'.
PARAMETERS p_ref   TYPE string LOWER CASE DEFAULT 'HEAD'.
PARAMETERS p_depth TYPE i DEFAULT 1.
PARAMETERS p_seed  TYPE string LOWER CASE OBLIGATORY.
PARAMETERS p_host  TYPE string LOWER CASE OBLIGATORY DEFAULT 'ssh.github.com'.
PARAMETERS p_port  TYPE string DEFAULT '443'.
PARAMETERS p_tmout TYPE i DEFAULT 120.

CLASS lcx_git DEFINITION INHERITING FROM cx_static_check FINAL.
  PUBLIC SECTION.
    METHODS constructor
      IMPORTING
        iv_text TYPE string.
    METHODS get_text REDEFINITION.
  PRIVATE SECTION.
    DATA mv_text TYPE string.
ENDCLASS.

CLASS lcx_git IMPLEMENTATION.
  METHOD constructor.
    super->constructor( ).
    mv_text = iv_text.
  ENDMETHOD.

  METHOD get_text.
    result = mv_text.
  ENDMETHOD.
ENDCLASS.

CLASS lcl_github_host DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
ENDCLASS.

CLASS lcl_github_host IMPLEMENTATION.
  METHOD zif_oassh_host_verifier~verify.
* GitHub's published host keys, as the SHA-256 of the key blob. Compare with
* https://api.github.com/meta and docs.github.com "GitHub's SSH key
* fingerprints"; in base64 these are the familiar SHA256:... strings:
*   ssh-ed25519 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
*   ssh-rsa     SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
    CONSTANTS lc_ed25519 TYPE x LENGTH 32
      VALUE 'F83898DF0BEF57A4EE24985BA598AC17FCCB0C0D333CC4AF1DD92BE14BC23AA5'.
    CONSTANTS lc_rsa TYPE x LENGTH 32
      VALUE 'B8D895CED92C0AC0E171CD2EF5EF01BA3417554A4A6480D331CCC2BE3DED0F6B'.

    DATA lv_fingerprint TYPE xstring.

    IF NOT ( iv_host = 'github.com' AND iv_port = '22' )
        AND NOT ( iv_host = 'ssh.github.com' AND iv_port = '443' ).
      RETURN.
    ENDIF.

    TRY.
        cl_abap_message_digest=>calculate_hash_for_raw(
          EXPORTING
            if_algorithm   = 'SHA256'
            if_data        = iv_host_key
          IMPORTING
            ef_hashxstring = lv_fingerprint ).
      CATCH cx_abap_message_digest.
        RETURN.
    ENDTRY.

    rv_trusted = xsdbool( lv_fingerprint = lc_ed25519 OR lv_fingerprint = lc_rsa ).
  ENDMETHOD.
ENDCLASS.

* git wire protocol v0 over the SSH channel, see
* https://git-scm.com/docs/pack-protocol and
* https://git-scm.com/docs/protocol-common (pkt-line framing).
CLASS lcl_upload_pack DEFINITION FINAL.
  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_ref,
        name TYPE string,
        sha1 TYPE string,
      END OF ty_ref.
    TYPES ty_refs TYPE STANDARD TABLE OF ty_ref WITH EMPTY KEY.

    METHODS constructor
      IMPORTING
        ii_exec            TYPE REF TO zif_oassh_interactive_exec
        iv_timeout_seconds TYPE i.
    METHODS read_advertisement
      RAISING
        zcx_oassh_error
        lcx_git.
    METHODS get_refs
      RETURNING
        VALUE(rt_refs) TYPE ty_refs.
    METHODS get_capabilities
      RETURNING
        VALUE(rt_capabilities) TYPE string_table.
    METHODS find_ref
      IMPORTING
        iv_name       TYPE string
      RETURNING
        VALUE(rs_ref) TYPE ty_ref
      RAISING
        lcx_git.
    METHODS fetch
      IMPORTING
        iv_want        TYPE string
        iv_depth       TYPE i
      RETURNING
        VALUE(rv_pack) TYPE xstring
      RAISING
        zcx_oassh_error
        lcx_git.
    METHODS get_shallow
      RETURNING
        VALUE(rt_shallow) TYPE string_table.
    METHODS get_messages
      RETURNING
        VALUE(rv_messages) TYPE string.

  PRIVATE SECTION.
    TYPES:
      BEGIN OF ty_pkt,
        flush   TYPE abap_bool,
        payload TYPE xstring,
      END OF ty_pkt.

    DATA mi_exec TYPE REF TO zif_oassh_interactive_exec.
    DATA mv_timeout_seconds TYPE i.
    DATA mv_buffer TYPE xstring.
    DATA mt_refs TYPE ty_refs.
    DATA mt_capabilities TYPE string_table.
    DATA mt_shallow TYPE string_table.
    DATA mv_messages TYPE string.

    METHODS read_pkt
      RETURNING
        VALUE(rs_pkt) TYPE ty_pkt
      RAISING
        zcx_oassh_error
        lcx_git.
    METHODS fill_buffer
      RAISING
        zcx_oassh_error
        lcx_git.
    METHODS read_sideband
      RETURNING
        VALUE(rv_pack) TYPE xstring
      RAISING
        zcx_oassh_error
        lcx_git.
    METHODS has_capability
      IMPORTING
        iv_name       TYPE string
      RETURNING
        VALUE(rv_has) TYPE abap_bool.
    CLASS-METHODS pkt
      IMPORTING
        iv_text       TYPE string
      RETURNING
        VALUE(rv_pkt) TYPE xstring.
    CLASS-METHODS to_text
      IMPORTING
        iv_payload     TYPE xstring
      RETURNING
        VALUE(rv_text) TYPE string.
ENDCLASS.

CLASS lcl_upload_pack IMPLEMENTATION.
  METHOD constructor.
    mi_exec = ii_exec.
    mv_timeout_seconds = iv_timeout_seconds.
  ENDMETHOD.

  METHOD get_refs.
    rt_refs = mt_refs.
  ENDMETHOD.

  METHOD get_capabilities.
    rt_capabilities = mt_capabilities.
  ENDMETHOD.

  METHOD get_shallow.
    rt_shallow = mt_shallow.
  ENDMETHOD.

  METHOD get_messages.
    rv_messages = mv_messages.
  ENDMETHOD.

  METHOD has_capability.
    rv_has = xsdbool( line_exists( mt_capabilities[ table_line = iv_name ] ) ).
  ENDMETHOD.

  METHOD read_advertisement.
* One pkt-line per ref, "<sha1> <name>\n", terminated by a flush-pkt. The
* first line carries the server capabilities after a NUL byte. An empty
* repository advertises the placeholder "capabilities^{}" instead of a ref.
    CONSTANTS lc_nul TYPE x LENGTH 1 VALUE '00'.

    DATA ls_pkt TYPE ty_pkt.
    DATA ls_ref TYPE ty_ref.
    DATA lv_offset TYPE i.
    DATA lv_capabilities TYPE xstring.

    DO.
      ls_pkt = read_pkt( ).
      IF ls_pkt-flush = abap_true.
        EXIT.
      ENDIF.

      IF mt_capabilities IS INITIAL.
        FIND FIRST OCCURRENCE OF lc_nul IN ls_pkt-payload IN BYTE MODE MATCH OFFSET lv_offset.
        IF sy-subrc = 0.
          lv_capabilities = ls_pkt-payload+lv_offset.
          lv_capabilities = lv_capabilities+1.
          SPLIT to_text( lv_capabilities ) AT space INTO TABLE mt_capabilities.
          ls_pkt-payload = ls_pkt-payload(lv_offset).
        ENDIF.
      ENDIF.

      SPLIT to_text( ls_pkt-payload ) AT space INTO ls_ref-sha1 ls_ref-name.
      IF ls_ref-name <> 'capabilities^{}'.
        INSERT ls_ref INTO TABLE mt_refs.
      ENDIF.
    ENDDO.
  ENDMETHOD.

  METHOD find_ref.
    READ TABLE mt_refs INTO rs_ref WITH KEY name = iv_name.
    IF sy-subrc <> 0.
      READ TABLE mt_refs INTO rs_ref WITH KEY name = |refs/heads/{ iv_name }|.
    ENDIF.
    IF sy-subrc <> 0.
      READ TABLE mt_refs INTO rs_ref WITH KEY name = |refs/tags/{ iv_name }|.
    ENDIF.
    IF sy-subrc <> 0.
      RAISE EXCEPTION NEW lcx_git( |ref { iv_name } is not advertised by the repository| ).
    ENDIF.
  ENDMETHOD.

  METHOD fetch.
* Request: want-line with capabilities, optional deepen, flush, done. The
* conversation is stateful over SSH, so all of it can be sent at once.
    CONSTANTS lc_flush TYPE x LENGTH 4 VALUE '30303030'.

    DATA lv_want TYPE string.
    DATA lv_request TYPE xstring.
    DATA lv_part TYPE xstring.
    DATA ls_pkt TYPE ty_pkt.
    DATA lv_line TYPE string.

    IF has_capability( 'side-band-64k' ) = abap_false.
      RAISE EXCEPTION NEW lcx_git( 'server does not offer side-band-64k' ).
    ENDIF.

    lv_want = |want { iv_want } side-band-64k|.
    IF has_capability( 'ofs-delta' ) = abap_true.
      lv_want = |{ lv_want } ofs-delta|.
    ENDIF.
    IF has_capability( 'no-progress' ) = abap_true.
      lv_want = |{ lv_want } no-progress|.
    ENDIF.
    IF iv_depth > 0.
      IF has_capability( 'shallow' ) = abap_false.
        RAISE EXCEPTION NEW lcx_git( 'server does not offer shallow fetches, set p_depth to 0' ).
      ENDIF.
      lv_want = |{ lv_want } shallow|.
    ENDIF.

    lv_request = pkt( |{ lv_want }\n| ).
    IF iv_depth > 0.
      lv_part = pkt( |deepen { iv_depth }\n| ).
      CONCATENATE lv_request lv_part INTO lv_request IN BYTE MODE.
    ENDIF.
    lv_part = pkt( |done\n| ).
    CONCATENATE lv_request lc_flush lv_part INTO lv_request IN BYTE MODE.
    mi_exec->exec_write( lv_request ).

* A shallow request is answered with "shallow <sha1>" lines and a flush-pkt.
    IF iv_depth > 0.
      DO.
        ls_pkt = read_pkt( ).
        IF ls_pkt-flush = abap_true.
          EXIT.
        ENDIF.
        INSERT to_text( ls_pkt-payload ) INTO TABLE mt_shallow.
      ENDDO.
    ENDIF.

* No "have" lines were sent, so the negotiation ends with a single NAK.
    ls_pkt = read_pkt( ).
    lv_line = to_text( ls_pkt-payload ).
    IF lv_line <> 'NAK'.
      RAISE EXCEPTION NEW lcx_git( |expected NAK, received "{ lv_line }"| ).
    ENDIF.

    rv_pack = read_sideband( ).
  ENDMETHOD.

  METHOD read_sideband.
* Each pkt-line starts with a band byte: 1 = pack data, 2 = progress and
* remote messages, 3 = fatal error. A flush-pkt ends the response.
    DATA ls_pkt TYPE ty_pkt.
    DATA lv_band TYPE x LENGTH 1.
    DATA lv_data TYPE xstring.

    DO.
      ls_pkt = read_pkt( ).
      IF ls_pkt-flush = abap_true.
        EXIT.
      ELSEIF ls_pkt-payload IS INITIAL.
        CONTINUE.
      ENDIF.

      lv_band = ls_pkt-payload(1).
      lv_data = ls_pkt-payload+1.
      CASE lv_band.
        WHEN '01'.
          CONCATENATE rv_pack lv_data INTO rv_pack IN BYTE MODE.
        WHEN '02'.
          mv_messages = mv_messages && zcl_oassh_ascii=>from_xstring_text( lv_data ).
        WHEN '03'.
          RAISE EXCEPTION NEW lcx_git( |remote error: { to_text( lv_data ) }| ).
        WHEN OTHERS.
          RAISE EXCEPTION NEW lcx_git( |unexpected side-band { lv_band }| ).
      ENDCASE.
    ENDDO.
  ENDMETHOD.

  METHOD read_pkt.
* pkt-line: four hex digits giving the total length including themselves,
* then the payload. "0000" is the flush-pkt. A payload starting with "ERR "
* reports a fatal server error.
    CONSTANTS lc_err TYPE x LENGTH 4 VALUE '45525220'.

    DATA lv_prefix TYPE xstring.
    DATA lv_hex TYPE string.
    DATA lv_length_x TYPE x LENGTH 2.
    DATA lv_length TYPE i.
    DATA lv_payload_length TYPE i.

    WHILE xstrlen( mv_buffer ) < 4.
      fill_buffer( ).
    ENDWHILE.

    lv_prefix = mv_buffer(4).
    lv_hex = to_upper( zcl_oassh_ascii=>from_xstring( lv_prefix ) ).
    IF strlen( lv_hex ) <> 4 OR lv_hex CN '0123456789ABCDEF'.
      RAISE EXCEPTION NEW lcx_git( |invalid pkt-line length "{ lv_hex }"| ).
    ENDIF.
    lv_length_x = lv_hex.
    lv_length = lv_length_x.

    IF lv_length = 0.
      rs_pkt-flush = abap_true.
      mv_buffer = mv_buffer+4.
      RETURN.
    ELSEIF lv_length < 4.
      RAISE EXCEPTION NEW lcx_git( |unexpected special pkt-line { lv_hex }| ).
    ENDIF.

    WHILE xstrlen( mv_buffer ) < lv_length.
      fill_buffer( ).
    ENDWHILE.

    lv_payload_length = lv_length - 4.
    rs_pkt-payload = mv_buffer+4(lv_payload_length).
    mv_buffer = mv_buffer+lv_length.

    IF xstrlen( rs_pkt-payload ) >= 4.
      lv_prefix = rs_pkt-payload(4).
      IF lv_prefix = lc_err.
        lv_prefix = rs_pkt-payload+4.
        RAISE EXCEPTION NEW lcx_git( |remote error: { to_text( lv_prefix ) }| ).
      ENDIF.
    ENDIF.
  ENDMETHOD.

  METHOD fill_buffer.
    DATA lv_chunk TYPE xstring.
    DATA lv_stderr TYPE string.

    lv_chunk = mi_exec->exec_read( mv_timeout_seconds ).
    IF lv_chunk IS NOT INITIAL.
      CONCATENATE mv_buffer lv_chunk INTO mv_buffer IN BYTE MODE.
      RETURN.
    ENDIF.

    IF mi_exec->exec_is_closed( ) = abap_false.
      RAISE EXCEPTION NEW lcx_git( |no data from git-upload-pack within { mv_timeout_seconds } seconds| ).
    ENDIF.

* The command ended early. GitHub explains why on stderr, for example
* "ERROR: Repository not found." when the deploy key belongs to another repo.
    TRY.
        mi_exec->exec_close( mv_timeout_seconds ).
        lv_stderr = mi_exec->get_stderr( ).
      CATCH zcx_oassh_error ##NO_HANDLER.
* Already reporting the early end below; the close failure adds nothing.
    ENDTRY.
    RAISE EXCEPTION NEW lcx_git( |git-upload-pack ended unexpectedly: { lv_stderr }| ).
  ENDMETHOD.

  METHOD pkt.
    DATA lv_data TYPE xstring.
    DATA lv_length TYPE x LENGTH 2.

    lv_data = zcl_oassh_ascii=>to_xstring( iv_text ).
    lv_length = xstrlen( lv_data ) + 4.
    rv_pkt = zcl_oassh_ascii=>to_xstring( to_lower( CONV string( lv_length ) ) ).
    CONCATENATE rv_pkt lv_data INTO rv_pkt IN BYTE MODE.
  ENDMETHOD.

  METHOD to_text.
    rv_text = shift_right( val = zcl_oassh_ascii=>from_xstring_text( iv_payload )
                           sub = |\n| ).
  ENDMETHOD.
ENDCLASS.

CLASS lcl_pack_check DEFINITION FINAL.
  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_info,
        version  TYPE i,
        objects  TYPE i,
        checksum TYPE string,
      END OF ty_info.

* Validates the header ("PACK", version, object count) and the trailing SHA-1
* over everything before it, see https://git-scm.com/docs/gitformat-pack .
    CLASS-METHODS check
      IMPORTING
        iv_pack        TYPE xstring
      RETURNING
        VALUE(rs_info) TYPE ty_info
      RAISING
        lcx_git.
ENDCLASS.

CLASS lcl_pack_check IMPLEMENTATION.
  METHOD check.
    CONSTANTS lc_signature TYPE x LENGTH 4 VALUE '5041434B'.

    DATA lv_word TYPE x LENGTH 4.
    DATA lv_body_length TYPE i.
    DATA lv_body TYPE xstring.
    DATA lv_trailer TYPE xstring.
    DATA lv_sha1 TYPE xstring.

    IF xstrlen( iv_pack ) < 32 OR iv_pack(4) <> lc_signature.
      RAISE EXCEPTION NEW lcx_git( 'received data is not a git packfile' ).
    ENDIF.

    lv_word = iv_pack+4(4).
    rs_info-version = lv_word.
    lv_word = iv_pack+8(4).
    rs_info-objects = lv_word.

    lv_body_length = xstrlen( iv_pack ) - 20.
    lv_body = iv_pack(lv_body_length).
    lv_trailer = iv_pack+lv_body_length.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_raw(
          EXPORTING
            if_algorithm   = 'SHA1'
            if_data        = lv_body
          IMPORTING
            ef_hashxstring = lv_sha1 ).
      CATCH cx_abap_message_digest.
        RAISE EXCEPTION NEW lcx_git( 'SHA-1 is not available' ).
    ENDTRY.

    IF lv_sha1 <> lv_trailer.
      RAISE EXCEPTION NEW lcx_git( 'packfile checksum mismatch' ).
    ENDIF.
    rs_info-checksum = to_lower( CONV string( lv_sha1 ) ).
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  PERFORM run.

FORM run.

  DATA lv_seed      TYPE xstring.
  DATA lv_seed_hex  TYPE string.
  DATA li_exec      TYPE REF TO zif_oassh_interactive_exec.
  DATA lo_git       TYPE REF TO lcl_upload_pack.
  DATA ls_want      TYPE lcl_upload_pack=>ty_ref.
  DATA lv_pack      TYPE xstring.
  DATA ls_info      TYPE lcl_pack_check=>ty_info.
  DATA lv_exit      TYPE i.
  DATA lx_error     TYPE REF TO cx_static_check.
  DATA lx_previous  TYPE REF TO cx_root.

  lv_seed_hex = to_upper( condense( p_seed ) ).
  IF strlen( lv_seed_hex ) <> 64 OR lv_seed_hex CN '0123456789ABCDEF'.
    WRITE / 'p_seed must be the 32-byte Ed25519 seed as 64 hex characters.'.
    RETURN.
  ENDIF.
  lv_seed = lv_seed_hex.

* GitHub runs the command itself rather than through a shell; only a quoted
* "owner/repo.git" path is accepted.
  IF p_repo CA `'"\ `.
    WRITE / 'p_repo must look like owner/repo.git.'.
    RETURN.
  ENDIF.

  TRY.
* ii_random is optional on SAP: zcl_oassh defaults to zcl_oassh_random_secure.
      li_exec = zcl_oassh=>connect(
        iv_host          = p_host
        iv_port          = p_port
        iv_user          = 'git'
        iv_private_seed  = lv_seed
        ii_host_verifier = NEW lcl_github_host( ) ).

      TRY.
          li_exec->exec_open(
            iv_command         = |git-upload-pack '{ p_repo }'|
            iv_timeout_seconds = p_tmout ).

          lo_git = NEW #(
            ii_exec            = li_exec
            iv_timeout_seconds = p_tmout ).
          lo_git->read_advertisement( ).
          IF lo_git->get_refs( ) IS INITIAL.
            RAISE EXCEPTION NEW lcx_git( 'the repository is empty' ).
          ENDIF.

          ls_want = lo_git->find_ref( p_ref ).
          lv_pack = lo_git->fetch(
            iv_want  = ls_want-sha1
            iv_depth = p_depth ).

          li_exec->exec_close( p_tmout ).
          lv_exit = li_exec->get_exit_status( ).
        CLEANUP.
          li_exec->close( ).
      ENDTRY.
      li_exec->close( ).

      ls_info = lcl_pack_check=>check( lv_pack ).

      WRITE: / 'repository:', p_repo.
      LOOP AT lo_git->get_capabilities( ) INTO DATA(lv_capability) WHERE table_line CP 'symref=*'.
        WRITE: / 'symref:', lv_capability+7.
      ENDLOOP.
      WRITE: / 'refs advertised:', lines( lo_git->get_refs( ) ).
      WRITE: / 'fetched:', ls_want-name, ls_want-sha1.
      LOOP AT lo_git->get_shallow( ) INTO DATA(lv_shallow).
        WRITE / lv_shallow.
      ENDLOOP.
      SKIP.
      WRITE: / 'packfile bytes:', xstrlen( lv_pack ).
      WRITE: / 'pack version:', ls_info-version.
      WRITE: / 'objects:', ls_info-objects.
      WRITE: / 'SHA-1 trailer OK:', ls_info-checksum.
      WRITE: / 'git-upload-pack exit status:', lv_exit.
      IF lo_git->get_messages( ) IS NOT INITIAL.
        SKIP.
        WRITE / 'remote messages:'.
        WRITE / lo_git->get_messages( ).
      ENDIF.

    CATCH cx_static_check INTO lx_error.
      WRITE: / 'git clone error:', lx_error->get_text( ).
* T100 message variables hold 50 characters, so the library's own text can cut
* off the cause; the original exception (for example the APC connect error)
* is kept as PREVIOUS with its full text.
      lx_previous = lx_error->previous.
      WHILE lx_previous IS BOUND.
        WRITE: / 'caused by:', lx_previous->get_text( ).
        lx_previous = lx_previous->previous.
      ENDWHILE.
  ENDTRY.

ENDFORM.
