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
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C09140AC85937816A03D2567D0EC6'.
    rv_data = rv_data && 'DA1BA842000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
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
    rv_data = rv_data && '727361000000030100010000018100D6F2AFDB6EC483ECC3214BFD308845DCC3C207CE3EF144C67F'.
    rv_data = rv_data && 'D21C45EB56DF77B33074340DA809E25CC94A9FA6CECEAD2AEFA3B4CD6F39EF7D551B6721FDBB4B8A'.
    rv_data = rv_data && '7CE1A998142F0D4CD96F0E6D36625E94786398EDEF64B61FDAD01BE2237F404B42DFF1C705F99DFC'.
    rv_data = rv_data && '121C20434AA88C2CD6305E2CFD675A3DEEA30791E3311CA27A1FFAE62A14BB5FBA0C21AB0735C5C8'.
    rv_data = rv_data && '8926D5F45D8332F28ABABE5C262B7D0102FBFCC85F8E7947474856842D46B1EEAF356907F2DC45A8'.
    rv_data = rv_data && '27B2C8AE28E43E9BA93F6DC1539A17F7B5B93375109F4B69C48AC3CCBD43B4BAD404032E04C578BC'.
    rv_data = rv_data && 'F79606EA64733E79CC6C900395601B938A1CDA556CC687D4730F028E8DC360CE39FBDF42BFB83138'.
    rv_data = rv_data && 'DB4E8990E814CA2CD35F747CDB7426B00FBC330AE8020D6672C5352DF93BF1B16845E8D592F7D14B'.
    rv_data = rv_data && '279F1C1222290BD0CC20C48B98411DBC92B1EAEFF2831D53326E87A0C177C1FFF602F257060D9D17'.
    rv_data = rv_data && '75185F72AF61475DCEE4A6F085F4A520D002C51D9D4B656B39238470903B262E9D4A8A40D5FEEF00'.
    rv_data = rv_data && '000020CDCBEFD27E2E1DAF9EE0C8FD0A81A25C98E30B15C87C08970D87A05E03CF94060000019400'.
    rv_data = rv_data && '00000C7273612D736861322D3235360000018099D96DBBFA4E1FBB99213978C70017BB5913EB27A1'.
    rv_data = rv_data && '48A3F166BF5215DC75AD806973A757EEDE97A88227FA6518E217EB456990A040A71E3191530D638F'.
    rv_data = rv_data && '56ACB645789CC8327FEB6AD69F96CECE6494447DA7E9E40ABE84CA3DBEFCF87D443BC288BE665915'.
    rv_data = rv_data && '2693E2F2C5F2B2AC433DE28FFF5A56064480719A76227F336FC1CE7F9CA752F2B17C81F7FDAD3CF8'.
    rv_data = rv_data && 'D6A37E1F5C9DF2FCB696DDB8E4E0A3AC342A2D1AB426A7A1F3C4194A6750CCD113A14E8E1AAB149C'.
    rv_data = rv_data && '05F82367B62936D5A04412AF0211BB7A67ABBC0E996F9840E90E98BBA1C23DF9E58101D61FC4D8E4'.
    rv_data = rv_data && '8E8249D1AED38CE46C2467E8F75D4985E31A36DBCAD66EC76F52CFCC98A183FB1231338CDB96643D'.
    rv_data = rv_data && 'D2B070593BB4EA22700346D2923A9D74B371843495110A54D839229F6082CF58F2080CA2F7F80962'.
    rv_data = rv_data && '8748C26F25E642A856BB5B61B74E626E63505BD237CF51B7DB96700FCA691329CE9A1BA2E3C42796'.
    rv_data = rv_data && '5058B034664B87D22B9E7CA9F282F293AB67204D87829989D4B672C362C4A26F6353A4B03AFB5C9B'.
    rv_data = rv_data && '1B5C1800000000000000000000000000000C0A1500000000000000000000BE47A33FB2C22467EEA6'.
    rv_data = rv_data && '9B40ED8F761686E4FAE64D879725F9A41119C0F061516AF207E9E868263F65069C38A2F8488A5F88'.
    rv_data = rv_data && '1F17F411FF01D83187B58920575FB0B068A5458DFF0806A9130DE63C4F591E013B69D3B0AEF6E3B5'.
    rv_data = rv_data && '11FF5397F91B4011E3E8D19DCF19024410B2A681F8E2B9174E8FD1CA06ED7B933F908C649C90F302'.
    rv_data = rv_data && 'D147580967D5C7EA617B53C7025E9FE7E23E7CE03664CCBECA9CD4DF7D4E6588AD9E54251AC198E5'.
    rv_data = rv_data && '2802A425DFB4BFBB39427CEA88FF63A8EB8EF629A9A1E86575F99C320E77212EBAFD5FB5998ECE9B'.
    rv_data = rv_data && '198B9A8F71D298C19A089A599C9AEB1D596C840973D0E18C3AF447ED8A38DC4342B5C2DBD50D4D28'.
    rv_data = rv_data && '83C83F64C764F5AB8274FE91CB393CD23F8EF9A7203123C1D1FE11E3D7859E9F6F9D4AF1F8131FB8'.
    rv_data = rv_data && '4E61F6D10991AC15DC5799CB78922C5E5F83BC9F9B6A75F6C9F3D5FB287AFE3C0C57E619704243D3'.
    rv_data = rv_data && '0842D75E0616EF93039C5D115CF1BC9BA8199027F6C0877BBC11ED60A3DFE85FB2B9B4F8E049B3DF'.
    rv_data = rv_data && '7CCF75D4D7CB15E995D010B6933E991CE8C92D9F7AABF753B11A9D430072D251BA13905D55684B12'.
    rv_data = rv_data && 'FAE70EBAE06F8665439DE4C3DFFE04CF4ED675CB2ABA006DB68EA1229DB8078F3AB4009D9A90ED29'.
    rv_data = rv_data && 'E007C74D870709B51AB5622C50E207C3E975740A4AEEAA421E4D3F0913C2B16995D3C7E43B42B002'.
    rv_data = rv_data && 'D04A83380FE7DC56AFED7689657D6DA68226096F0B4A795BCF0FC28140D4887ECC89CE5B95F9DE28'.
    rv_data = rv_data && 'ADB9AF2224487B40A412A72D408CB91E95E5DC63BAF8D24EF80BAC83965661A77E378E6E5BF5D89A'.
    rv_data = rv_data && '6589FA17BD3948F6340D1091672F32617DD4B96FA6EBDD45AD3FD43095CF6202E2AC5413A43D0CE4'.
    rv_data = rv_data && '63711A9081502465EF9A158BE3CEC942D2A29C490AE8A500E243EEB6A3579E8D23C08B5F44515604'.
    rv_data = rv_data && '304B7876A4AC2071314DB1DBA276332B881A6F366FEEA78B0F8C2A4AB992EAADC01E2495964B1106'.
    rv_data = rv_data && '247C7929AB69F0D6EDDB943C35208F6B05C7CA3E90DF1AC6DEAA57EB1B2F01949695F65299AD94F6'.
    rv_data = rv_data && 'C8E22C3B7E97660C32A5A91518E7406066EB05D7602BDE9AB783015ED73851704D88768A928F08DB'.
    rv_data = rv_data && '2DDD880034152E8F8B9913EC23593A9AA8783C3A06AADFE8DF1AD7B5FF553B6F3576F3D9FF11B853'.
    rv_data = rv_data && 'C15E81FF9FD8DDCAE04CCE22DB088D219AB096B82D4C951A647734AB7EE9C7E1DC132BC6C93B3921'.
    rv_data = rv_data && 'B88DE7C753D2F1F7581599EC043599AA2A0544C8F9CD55F2B1D28D572155348925CF1CB69188EE5A'.
    rv_data = rv_data && '96317C5F032349433C30111C5388E6DF38CE76541E819C8B5C0C211AEC3E89241014ED48000155BE'.
    rv_data = rv_data && '774D436EF75256CE7F38FF9F8F93DD775DDCE62FB4E0A2D59B591925E299035AD0F96BD68598AC05'.
    rv_data = rv_data && '7B9C6A84784F34B70C258A6DA23CAF16835699F96A86F3FC2920C5D53CC177EB5DBD9ED3E9584F98'.
    rv_data = rv_data && '8DF4E7C65C27A0BCE506A976BE677AFB312034B6AA7D8C3980CFB4E063245CD01D5AFCD1D92F0602'.
    rv_data = rv_data && '693C3889E9EBF27250A508BC7D63538747B74DF94EC3B76972DB8C462A3344ABEB280500D0B1B479'.
    rv_data = rv_data && '64DBF4FC498193E29F6A20FCFD4E178DDAC991A8CC65BF865FBA4F380CD3AF41D66D906C62E714E5'.
    rv_data = rv_data && 'A4A7C66EA530E3281A2040CDF7A0D13701FA0185FCF02758BBEFEF113512F4D4FDF6E458C7D962A5'.
    rv_data = rv_data && '607813A03A3DF690F9413038E651'.
  ENDMETHOD.


  METHOD recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A0000011C0614ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D0000000C7273612D736861322D323536000000286165733132382D6374722C'.
    rv_data = rv_data && '63686163686132302D706F6C7931333035406F70656E7373682E636F6D000000286165733132382D'.
    rv_data = rv_data && '6374722C63686163686132302D706F6C7931333035406F70656E7373682E636F6D0000000D686D61'.
    rv_data = rv_data && '632D736861322D3235360000000D686D61632D736861322D323536000000046E6F6E65000000046E'.
    rv_data = rv_data && '6F6E6500000000000000000000000000ABABABABABAB0000002C061E00000020E3712D851A0E5D79'.
    rv_data = rv_data && 'B831C5E34AB22B41A198171DE209B8B8FACA23A11C624859ABABABABABAB0000000C0A15ABABABAB'.
    rv_data = rv_data && 'ABABABABABABC11819C9657DABDB3D7A637E15F290C07E6D9C4E3E1041011C751E2F75587B24F313'.
    rv_data = rv_data && 'F01DF3B8E2F679BEE766EF91EA83090103A5FACB18FCBF85FF29A6FD4236CEAE2413867EDBC96F40'.
    rv_data = rv_data && '282B469AD166E88EB907E81A50D817A99C3BD1146E397F36CBDD99E39160A6A3F6E73CD216BA3B28'.
    rv_data = rv_data && 'BB24A4CE983C3BE561DAF94474E865A8ED129676AF19702D6483F762C55F1187EEAD55B5DE0B1171'.
    rv_data = rv_data && '22544473FFD2D75A87C5F1185A7D8A139DD67D976CA47C5811E2CC2E07830B3D7972AE16C9EB097F'.
    rv_data = rv_data && 'C4036920C06FE859083D67481E8BC3AF2EA4DE8F6A5DC80BFEDEE2378AC764BAAA64D9A85BD3E1AD'.
    rv_data = rv_data && '884362D80AAC9BF037E6C8059128F4B6645046D3D645B9DBF05C81EAC509CA1B5B740E1EBDE0D851'.
    rv_data = rv_data && '4DF030C52D0D399897757795317FC5C15F54FCC6C9B7C706399762C8986F01E7AC0DBE45B9787C82'.
    rv_data = rv_data && '7005BDC2BA9BE708E63986CBE926BBCC2758F4FF4D6E570D898BC2CAA9A0E533A0A1833B43C50A8B'.
    rv_data = rv_data && 'A7D6B71E1CB4ABF163ED2F783717'.
  ENDMETHOD.

ENDCLASS.
