CLASS ltcl_test DEFINITION DEFERRED.
CLASS zcl_oassh DEFINITION LOCAL FRIENDS ltcl_test.

CLASS lcl_host_verifier DEFINITION FINAL.
  PUBLIC SECTION.
    INTERFACES zif_oassh_host_verifier.
ENDCLASS.

CLASS lcl_host_verifier IMPLEMENTATION.
  METHOD zif_oassh_host_verifier~verify.
    rv_trusted = abap_true.
  ENDMETHOD.
ENDCLASS.

CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    METHODS on_open_sends_version FOR TESTING RAISING cx_static_check.
    METHODS server_version_starts_kex FOR TESTING RAISING cx_static_check.
    METHODS execute_returns_result FOR TESTING RAISING cx_static_check.
    METHODS global_request FOR TESTING RAISING cx_static_check.
    METHODS transport_messages FOR TESTING RAISING cx_static_check.
    METHODS execute_timeout FOR TESTING RAISING cx_static_check.
    METHODS recorded_session FOR TESTING RAISING cx_static_check.
    METHODS recorded_inbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS recorded_outbound
      RETURNING VALUE(rv_data) TYPE xstring.
    METHODS build_ssh RETURNING VALUE(ro_ssh) TYPE REF TO zcl_oassh.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD build_ssh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    ro_ssh = NEW #(
      ii_socket        = NEW zcl_oassh_socket_mock( )
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_user          = 'test'
      iv_password      = 'test' ).
  ENDMETHOD.

  METHOD transport_messages.
* RFC 4253 section 11 control messages are handled centrally and consumed
    DATA lo_ssh TYPE REF TO zcl_oassh.

    " IGNORE (02): string "x"
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '020000000178' ) ).

    " DEBUG (04): always_display=false, "hi", ""
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '040000000002686900000000' ) ).

    " UNIMPLEMENTED (03): sequence number 7
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true( lo_ssh->handle_transport_message( '0300000007' ) ).

    " DISCONNECT (01): reason 11 (by_application), "gone", ""
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_true(
      lo_ssh->handle_transport_message( '010000000B00000004676F6E6500000000' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_disconnect_reason( )
      exp = zcl_oassh_message_1=>c_reason-by_application ).

    " a non-control message is not consumed
    lo_ssh = build_ssh( ).
    cl_abap_unit_assert=>assert_false( lo_ssh->handle_transport_message( '5E00000000' ) ).
  ENDMETHOD.

  METHOD global_request.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    lo_mock = NEW #( ).
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = lo_mock
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_user          = 'test'
      iv_password      = 'test' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->process_global_request( '5000000004686F73740100000003616263' )
      exp = '52' ).
    cl_abap_unit_assert=>assert_initial( lo_ssh->process_global_request( '5000000004686F737400' ) ).
  ENDMETHOD.

  METHOD execute_returns_result.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_output TYPE string.
    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->connect( ).
    lo_ssh->mo_channel = NEW #( ).
    lo_ssh->mo_channel->open( ).
    lo_ssh->mo_channel->receive( '5B00000000000000070020000000008000' ).
    lo_ssh->mo_channel->exec( 'echo hi' ).
    lo_ssh->mo_channel->receive( '6300000000' ).
    lo_ssh->mo_channel->receive( '5E000000000000000368690A' ).
    lo_ssh->mo_channel->receive( '5F000000000000000100000003657272' ).
    lo_ssh->mo_channel->receive( '62000000000000000B657869742D7374617475730000000000' ).
    lo_ssh->mo_channel->receive( '6100000000' ).
    lo_ssh->mv_command_done = abap_true.
    lv_output = lo_ssh->execute( 'echo hi' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = |hi\n| ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_stderr( )
      exp = 'err' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_exit_status( )
      exp = 0 ).
    lo_ssh->close( ).
    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
  ENDMETHOD.


  METHOD execute_timeout.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA lx_error TYPE REF TO zcx_oassh_error.
    DATA lv_reason TYPE i.
    lo_ssh = build_ssh( ).
    TRY.
        lo_ssh->execute(
          iv_command         = 'echo hi'
          iv_timeout_seconds = 1 ).
      CATCH zcx_oassh_error INTO lx_error.
        lv_reason = lx_error->get_reason( ).
    ENDTRY.
    cl_abap_unit_assert=>assert_equals(
      act = lv_reason
      exp = zcx_oassh_error=>c_reason-timeout ).
  ENDMETHOD.


  METHOD recorded_session.
* Captured from the pinned OpenSSH 10.3 CI container with fixed AB randomness.
* This drives the real client from version exchange through encrypted exec.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lv_output TYPE string.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).
    lo_mock->simulate_open( ).
    lo_mock->set_replay( recorded_inbound( ) ).

    lv_output = lo_ssh->execute( 'printf open-abap-ssh' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_output
      exp = 'open-abap-ssh' ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->get_exit_status( )
      exp = 0 ).
    cl_abap_unit_assert=>assert_true( lo_ssh->mo_transport->is_strict_kex( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = recorded_outbound( ) ).
    lo_ssh->close( ).
    cl_abap_unit_assert=>assert_false( lo_mock->is_connected( ) ).
  ENDMETHOD.

  METHOD on_open_sends_version.

    DATA lo_mock   TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh    TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.

    lo_mock = NEW zcl_oassh_socket_mock( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( ).
    li_verifier = NEW lcl_host_verifier( ).

    CREATE OBJECT lo_ssh
      EXPORTING
        ii_socket        = li_socket
        ii_random        = li_random
        ii_host_verifier = li_verifier
        iv_user          = 'test'
        iv_password      = 'test'.

    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).

    lo_mock->simulate_open( ).

    " the client version string, SSH-2.0-abap followed by CR LF
    cl_abap_unit_assert=>assert_equals(
      act = lo_mock->get_sent( )
      exp = '5353482D322E302D616261700D0A' ).

  ENDMETHOD.


  METHOD server_version_starts_kex.
    DATA lo_mock TYPE REF TO zcl_oassh_socket_mock.
    DATA lo_ssh TYPE REF TO zcl_oassh.
    DATA li_socket TYPE REF TO zif_oassh_socket.
    DATA li_random TYPE REF TO zif_oassh_random.
    DATA li_verifier TYPE REF TO zif_oassh_host_verifier.
    DATA lo_decoder TYPE REF TO zcl_oassh_packet.
    DATA lo_stream TYPE REF TO zcl_oassh_stream.
    DATA ls_kexinit TYPE zcl_oassh_message_20=>ty_data.
    DATA lv_sent TYPE xstring.
    DATA lv_wire TYPE xstring.
    DATA lv_version TYPE xstring.
    DATA lv_client_length TYPE i.
    DATA lv_trailing TYPE xstring VALUE 'AABB'.

    lo_mock = NEW #( ).
    li_socket = lo_mock.
    li_random = NEW zcl_oassh_random_fixed( iv_pattern = 'AB' ).
    li_verifier = NEW lcl_host_verifier( ).
    lo_ssh = NEW #(
      ii_socket        = li_socket
      ii_random        = li_random
      ii_host_verifier = li_verifier
      iv_user          = 'test'
      iv_password      = 'test' ).
    li_socket->set_handler( lo_ssh ).
    li_socket->connect( ).
    lo_mock->simulate_open( ).
    lv_version = zcl_oassh_ascii=>to_xstring( 'SSH-2.0-OpenSSH_9.6' ).
    CONCATENATE lv_version zcl_oassh_ascii=>c_cr_lf INTO lv_version IN BYTE MODE.
    CONCATENATE lv_version lv_trailing INTO lv_version IN BYTE MODE.
    lo_mock->simulate_message( lv_version ).
    cl_abap_unit_assert=>assert_equals(
      act = lo_ssh->mo_stream->get( )
      exp = 'AABB' ).

    lv_sent = lo_mock->get_sent( ).
    lv_client_length = xstrlen( zcl_oassh_ascii=>to_xstring( 'SSH-2.0-abap' ) ) + 2.
    lv_wire = lv_sent+lv_client_length.
    lo_decoder = NEW #( ii_random = li_random ).
    lo_stream = NEW #( lo_decoder->decode( lv_wire ) ).
    ls_kexinit = zcl_oassh_message_20=>parse( lo_stream ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_kexinit-cookie
      exp = 'ABABABABABABABABABABABABABABABAB' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_kexinit-kex_algorithms[ 1 ]
      exp = 'curve25519-sha256' ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists( ls_kexinit-kex_algorithms[ table_line = 'kex-strict-c' ] ) ) ).
    cl_abap_unit_assert=>assert_true(
      xsdbool( line_exists(
        ls_kexinit-kex_algorithms[ table_line = 'kex-strict-c-v00@openssh.com' ] ) ) ).
  ENDMETHOD.


  METHOD recorded_inbound.
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C0914042DD784EE23C7BD6BE4DAF2'.
    rv_data = rv_data && '321080B8000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
    rv_data = rv_data && '32353531392D7368613531322C736E747275703736317832353531392D736861353132406F70656E'.
    rv_data = rv_data && '7373682E636F6D2C637572766532353531392D7368613235362C637572766532353531392D736861'.
    rv_data = rv_data && '323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D73'.
    rv_data = rv_data && '6861322D6E697374703338342C656364682D736861322D6E697374703532312C6578742D696E666F'.
    rv_data = rv_data && '2D732C6B65782D7374726963742D732D763030406F70656E7373682E636F6D000000396563647361'.
    rv_data = rv_data && '2D736861322D6E697374703235362C7373682D656432353531392C7273612D736861322D3531322C'.
    rv_data = rv_data && '7273612D736861322D3235360000006C63686163686132302D706F6C7931333035406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D40'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C616573323536'.
    rv_data = rv_data && '2D6374720000006C63686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165'.
    rv_data = rv_data && '733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E'.
    rv_data = rv_data && '636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D637472000000D5'.
    rv_data = rv_data && '756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F7065'.
    rv_data = rv_data && '6E7373682E636F6D2C686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C68'.
    rv_data = rv_data && '6D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65'.
    rv_data = rv_data && '746D406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D'.
    rv_data = rv_data && '313238406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D'.
    rv_data = rv_data && '3531322C686D61632D73686131000000D5756D61632D36342D65746D406F70656E7373682E636F6D'.
    rv_data = rv_data && '2C756D61632D3132382D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362D'.
    rv_data = rv_data && '65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373'.
    rv_data = rv_data && '682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C756D61632D363440'.
    rv_data = rv_data && '6F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D7368'.
    rv_data = rv_data && '61322D3235362C686D61632D736861322D3531322C686D61632D73686131000000156E6F6E652C7A'.
    rv_data = rv_data && '6C6962406F70656E7373682E636F6D000000156E6F6E652C7A6C6962406F70656E7373682E636F6D'.
    rv_data = rv_data && '00000000000000000000000000000000000000000000000003640B1F00000197000000077373682D'.
    rv_data = rv_data && '7273610000000301000100000181008F92B25F055916887858705B663B653878AC784256C4AE6E45'.
    rv_data = rv_data && '1B70BC5FF383F654555DDD782488B7BBDA70DAD14B92520C6986F590FE665A0AEE42FC7A2B86076F'.
    rv_data = rv_data && '5796EC366768D79C0849CC3EBB3A18A7B2BA7F0F40010BB24F6ED32A7DBBFA6CEE79C9A1FD53D50A'.
    rv_data = rv_data && '1037F6FC8F2D32DC4B2A9B79DBFECEBF8A5A39D553DF7098045501F90A1C0EEB42DF5502578FC5C5'.
    rv_data = rv_data && '53A32D4E87D6ACD9A039D0662F8342FB45B08278C3C5F5CBE800483F17C90147A597A08A84F61CCD'.
    rv_data = rv_data && '7113B755245DA3BF39178C71CA76F7B179B3A79097B46A3C8154943BC7048C3D7DC3FB96EAD8A885'.
    rv_data = rv_data && '4177BDAC97F5B1A465385F13D218F1D10806C9EF3C8BC45030B5D55AF1FB80470A00CFEB17875144'.
    rv_data = rv_data && '6AE2002534207C1AFAB7B874F6F1D0F404F92A6C25E8CF8A9B1FB9ABF1EE912264E8131C42EC7F4C'.
    rv_data = rv_data && 'F6064ACE3E3337065FC4A80D1E12013F21955FFC7C0FE767499B332C0288D5CA86FCB55A472B5900'.
    rv_data = rv_data && 'E053B4E91F90FE562B79BB1CED197F21083FE94FDF12C7301ABCE1B4E8320DCC1D7EF3E9B1591900'.
    rv_data = rv_data && '0000209AB0B42BD8D302DF4E68906808D7BE9E4CAEE1B073CB3F906065E4D68820743C0000019400'.
    rv_data = rv_data && '00000C7273612D736861322D32353600000180482C2D805356506C7F255FC22EDCB614EC71E0EDCB'.
    rv_data = rv_data && '69EFB1C67428F9D0EFBDC53E6703B2DDFFEC274D3B2F5D3F183BA22BCBE6349E7B6BE3AB33112A54'.
    rv_data = rv_data && 'D0E27093997BCB0CBF591AA27B61C2B48C160EE53246630772E28699E7557D163D8A6D0FE11AC29D'.
    rv_data = rv_data && '8AAAADCC8F46FDFDD0EDE4E7A70BF30F17ABC459C2FF312175BDEE497DF351756F9008DAF2A384C3'.
    rv_data = rv_data && '00B56EA3381D4E394CF33B377A46B356783F7A533C2BE19F2AFFC4B41873E641982BC6063A7961DD'.
    rv_data = rv_data && 'EAFF052E8624CD0D3C84797194BAB47BBC132BEE0BB0B6B44C58966669F52429927D2F76B15D5EA3'.
    rv_data = rv_data && '2FF6F79DE1FF64C5CE55EA825AA38C43CC466711792D8FAAF14BF4A3B0D1F913ECA9F3FB945F12E4'.
    rv_data = rv_data && 'A7E63AEAA325A2CFB751EEED7CE450A7476FB46FF12B2FA315BB62300B6639FC02928251F4989C6B'.
    rv_data = rv_data && '943BC32D1848967A012D76C02DD7FDDDB0CF6B05D8F7183E004EAE518903F55B5833D3AD45C3DC51'.
    rv_data = rv_data && 'CBE220CCB82B84DC9A73372D619C45A07F60365D9FCBCB26368802BEBBF124C510F13AC7CEBE9E01'.
    rv_data = rv_data && '0D545F00000000000000000000000000000C0A150000000000000000000023B9A339CAF21EEDE2C1'.
    rv_data = rv_data && '5C3E6B466F35AEFD50373191A5C19DA3EA79A6F8AF68A4352576646819D59A1D6ABDBD52C1AEB152'.
    rv_data = rv_data && '4A1E418201234A226734C0BC50F414DF4942E31A56F4D223FE6F849F5E4CFCE29F91DADB864D0349'.
    rv_data = rv_data && 'C403A31AA506C6FCDCFC9A7861AA66B011D694FAACDA54C6BBAED36B7EFDDAEE3594E94AE2287C6F'.
    rv_data = rv_data && '3D6A3D3D694BCB7DCE1BA5C5E075F1E14639CC7BBB3E8A3E4E02F360E2411EE68C2FF19FEA87D89B'.
    rv_data = rv_data && '6D551E3DA13A82899D944C8C0ED37BA7393A87DCBC56D94409D7FB5FE7B59BEC9CEB8C8E4A92786F'.
    rv_data = rv_data && 'F71B58FE4E20C0EF6369E97C9CA233F2332D237699DB1DA43CA9039254499742075BF67E7F293A78'.
    rv_data = rv_data && '864AA47D821A88A96ACA5E67A39E1823596735A77D508785BC315A274766937C6B50E9787431EADA'.
    rv_data = rv_data && '0B56DD0764FAC302FAFA573078D1DC0DF98D3CC2E99DCAC69529FB923826C99974368AD0D20C12AF'.
    rv_data = rv_data && '7CEBF65BF3618D8229873160CF8EDD67EA1DAA661AD1303FDDF25FDD30CABE4F5E2D408A9885D19F'.
    rv_data = rv_data && '32FC88EAB603F8DFCE281B3C5D8804942271261312AE36C79D3EA9D985F6CB19A0BDD2C5A7F39C54'.
    rv_data = rv_data && 'EAC3835E8662C42F1BC7840942C4C2DD3232A354CFF789858E9FBF2FBE947029EB9A62288E5D44F7'.
    rv_data = rv_data && 'E5E5765D37415C40AD316E6676310E0F89EFFA3C4FE14B723D39BB246B1362E3A6DB4EE0F38CD896'.
    rv_data = rv_data && 'E8A5755CEACB3D313B778D67A05587BA424AF4380B61D224B5D3D28684020FD2D54AEF503113E992'.
    rv_data = rv_data && 'A040F59016B2A0DBF301DF6DCDB82C80EF2507C7DD4B43A3A4FA6A9B3A2B5AE3BAD8E31BF1EE2C60'.
    rv_data = rv_data && '51294D1B0AF0CE07F6A1E91A5DC93E06B6A182B206811537084433BC12154C5C80F8464DD3739696'.
    rv_data = rv_data && '69CAD8EB1AABEC58242D00C5BEA350A1DB1AA7A3A4E496DE8BD6C046B260C4B3CC37B3DE52E040EC'.
    rv_data = rv_data && '471821FD44AE8F044EF9532037961B00D1CC34ACF858BDB6D1D39A1033A2AD3D0051119B6C569023'.
    rv_data = rv_data && '8036BAA6943297A88FE9A9B9CAE69BB64079945D3DF319A4EDD1AAD94F6E654B1F5CFC0D0A919050'.
    rv_data = rv_data && 'C6BE3BA7B8FC6A65655FC3EA80C0C4D88DBE811A356D7CF3734AD53A4DAD35CCD64C52616FF05EA0'.
    rv_data = rv_data && 'E18C34125039B04FDA90788162C0B9872128C02B2D5219A87211CB6628DAFDBFFA54B676175EC773'.
    rv_data = rv_data && '197B85081778DBE4F818673B2E416CF36D01EAD5AAF43DCDBEF7068992849546B85A4F537CBBADC2'.
    rv_data = rv_data && '5A9646E46419BFA3CF33219C788C37B02F7F90745F61E35850DEDDD3E04D6DFF2578F8F44766580B'.
    rv_data = rv_data && '853E49BBCD23FD7EB1CF0EB3FE4C531EA7B5560139884E80D7BF907A7A3524A48E957A9C6D7B1F8E'.
    rv_data = rv_data && '68EADC5E4A942C119708D0A0D3429A8F7FC2F31BF6B63A2EBB0C69AFC0947F1800B4FB5CFA1FC6DE'.
    rv_data = rv_data && '1037838F86644F41D2AF83873E02397A15C8D5FF9D4B027853579A7081DD06429DDF5E9AAD71154C'.
    rv_data = rv_data && '0B69E10A07834EA13A600391CCD1BEED7C011E2B7450A379E43D14D70AE025C5CDC33684D51FCC6B'.
    rv_data = rv_data && '1408C3E246C725555A860B38E8127E9F556D065495757D9ABB971A1F1D05EAF10ECB340035338E07'.
    rv_data = rv_data && '48689203F14A4E5D64E0B57096653030C0C0908A765E86A1AC803B42EEB408BAE9B94DA929755429'.
    rv_data = rv_data && '2B19A69CCD6F668A67FA17D59E1A4D877AE0D927A3463C90418494AC3F489D1C2C58E3E761083355'.
    rv_data = rv_data && 'E7D773B637110EC92B936551DAFF'.
  ENDMETHOD.


  METHOD recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A000000C40814ABABABABABABABABABABABABABABABAB0000003B'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6B65782D7374726963742D632C6B65782D7374726963'.
    rv_data = rv_data && '742D632D763030406F70656E7373682E636F6D0000000C7273612D736861322D3235360000000A61'.
    rv_data = rv_data && '65733132382D6374720000000A6165733132382D6374720000000D686D61632D736861322D323536'.
    rv_data = rv_data && '0000000D686D61632D736861322D323536000000046E6F6E65000000046E6F6E6500000000000000'.
    rv_data = rv_data && '000000000000ABABABABABABABAB0000002C061E00000020E3712D851A0E5D79B831C5E34AB22B41'.
    rv_data = rv_data && 'A198171DE209B8B8FACA23A11C624859ABABABABABAB0000000C0A15ABABABABABABABABABAB4123'.
    rv_data = rv_data && '47188B8C6D6BAACEC2CB568BB5D26B90736550E5503E27C87F1946B0EE918545D01C825813CE54DE'.
    rv_data = rv_data && '2D507A82EFEB86416CCD81E22CBDF5BD4896AC5EEA877A2D74CA37399D04CBAF749BD1298AA57D25'.
    rv_data = rv_data && 'FA73012121D00E33F8EDB1117AD9B1BB179941C7F281E80D64776211ACDAF0607207B83CF41BE152'.
    rv_data = rv_data && 'A45BD226A9699526CFC9327D32680A87CF2CC0E4415BDFAAA70306B10931BC2781DC0ED21D396568'.
    rv_data = rv_data && 'E11027DA63902D2D9E23EAC65D5BD5B5C1BAFF7F1B71CFDB9B8D0F7084EDF534814D14A794A82B59'.
    rv_data = rv_data && '2E1E250EABB27F147D9526221CE67B138B9E5D62D94B402F166265E1346F701780E33F9D01FBCAFF'.
    rv_data = rv_data && 'DDEE5ADA10386C5884BC266157A622B5094FFCE841B5B1201324E7C4E45A9616687E7390BC12AF66'.
    rv_data = rv_data && 'DDD91C0BB1755017907F55DDC21D05C82A4F8E1744E8E44D0156CB486646CD416CD0686E598C8395'.
    rv_data = rv_data && 'B8A62AD7599166F6044EEB0B96AC5932EA5C75C273CBBD9C23DC79A12C947021D4EF8ACB84FA6883'.
    rv_data = rv_data && '25344EACAA1C'.
  ENDMETHOD.

ENDCLASS.
