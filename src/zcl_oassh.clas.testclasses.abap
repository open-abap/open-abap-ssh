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
    rv_data = rv_data && '5353482D322E302D4F70656E5353485F31302E330D0A0000040C091443F1D2E12DC7F537D8F09BD7'.
    rv_data = rv_data && 'F0A014F0000000DF6D6C6B656D3736387832353531392D7368613235362C736E7472757037363178'.
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
    rv_data = rv_data && '727361000000030100010000018100B2AF1D276E0F9B0C787EA4DA46A7551D0011B5F14B8FA6EB82'.
    rv_data = rv_data && '59DA6045D8579B75E1C144F566DECD4A53A6DBD5C1F940CD911DC056C4A47FF4FCE866C5C610BECE'.
    rv_data = rv_data && '594E16E80EBC93ADA4B60A3968F96E25F8720A545B8033C0B43AD192068350BA708D4EC883BA3BC7'.
    rv_data = rv_data && '21650F4BE13DA0C27BB8D484C81FBFC2A47C3F48C12E9A40BBE874FE8B1A92A2E2EE1187FACA0234'.
    rv_data = rv_data && '39D8682CFA399AB5EF4CF90913205F6C9A1D18B11D62487518DA188C389B64951AC8E3F02A584773'.
    rv_data = rv_data && '173CB999ABD89E4D717DE876ACA2EE2C1442423D090E07C1B7262A802D173D85FCE5810CB3BEC192'.
    rv_data = rv_data && 'CBA24B1F7965B34FF307D5BF181CA48957350ACD3BD0291FB600B366B5FF1F229F22FDCFB8671981'.
    rv_data = rv_data && 'ED31939CB08402DFCEACAE87E11AE1F674D55BA9A193BDD754A4ACBCBDBD3CDDEE4002DD2BC10687'.
    rv_data = rv_data && '6574B203C1D84CA09F664CF8A45674A9652DA7426E9961BAD50679F939F400584E1BF2ADBE23A9BE'.
    rv_data = rv_data && '2034AE9AB22A4373AAD0CD2A297B59CE9330C54D43EE63F26D2C3CDC058364575DB9E2C2FC7C8F00'.
    rv_data = rv_data && '00002023119DBE7722B83E3951F1DDCCC4EBC1A7860DD118AABC0BAC28692DEACF4C530000019400'.
    rv_data = rv_data && '00000C7273612D736861322D3235360000018058DDBE1361A47A549894D80344737CC5234B9D82C2'.
    rv_data = rv_data && 'CD65171F2079235946CCB0F4D28FCB22FAD42366A52E2585BCF157D7019B7D8D471D034D4742599E'.
    rv_data = rv_data && '39CC59249197DC00EB1D1349446EEFD205D9E0E60E87217242F5B53FD8B6B9EFA8C10B6ED9E2AC5B'.
    rv_data = rv_data && '033199DE20296F08BAD9834D3F537DCA9A112BB6BA8801A84A636CE0F1A569E6EC15B75C7749BAAD'.
    rv_data = rv_data && '90BFB546EE6EE6BA75AF23B46622BDE417D9DDFE1CD775D8CBD1896F63674BB592B45951BBEA3AF0'.
    rv_data = rv_data && '03DD2D502741ADDB0FC68ADC24BF4AB1829FB9031B871640B5FA715BE850C45D0F70366BD02A505E'.
    rv_data = rv_data && '7C4C0805A65B678A589AEB3C6139C66CA6B5E800D6955BCB74BBBB95739E99CC6DEF6CEB9624801B'.
    rv_data = rv_data && 'F3038AA7B7C325F0BA97D454E9D5C9A4A128B70A984D2A2782B5850556267AF32B0BB0957B48A92F'.
    rv_data = rv_data && 'CBD9738780C6A06509967A94E7225633E23ED848CE743309B226028AF28C37C844C784181AFEE3D5'.
    rv_data = rv_data && '7FABAD167EB5655009BC30DDC7B302906307011716B98BA5A802AA358021BED4E70CB0A58A2975A5'.
    rv_data = rv_data && '24C70A00000000000000000000000000000C0A1500000000000000000000B838FC1F35149D60FE92'.
    rv_data = rv_data && '75D35EDFEDB9523E02987B505368022B9E99C5E14E7ACFC90FE22C20B6AC038095441F79D87208D3'.
    rv_data = rv_data && '57A122D888FA72E024D3420B5A4F04837E51CC281863F0B9F1F9E684CD1628A0A4AE19D165064EAD'.
    rv_data = rv_data && 'E0BD929B90577AE1D730DDE427B0ED7074CF1A2E52B073BE30C83A77796B3BD7A8F226435D57A60D'.
    rv_data = rv_data && 'F7259FBA71DCFBB01945F05E545EF79EF2FAA21DAB5CD0FE117E4D51D7B9D59193A709DCB4004CD4'.
    rv_data = rv_data && '6EE2876B692D53A82AC2757739474EDC438EB54407E22909AB35B7865860D7FFA1F1AB00448D55FF'.
    rv_data = rv_data && 'A201C856E80FDB48A4CB0A172CD852FD114AE75AA334050E6DB25C457938988958B255FAC051F855'.
    rv_data = rv_data && '731B4E5242BF5392D15B5F94B071BF15E494A6EF247EF0E4D7E0EC57FC8345587E05B61A1B86C60F'.
    rv_data = rv_data && '6E65AA595EEEDF1353208569D8DD8396CBDD77A1D06FF570006344FB0FCB555991FBDEB21ED51869'.
    rv_data = rv_data && 'A97EB30DB90AF6F8AD929519D1924050B094F16BDECA26481DAA7D5A8C3D00A9B22E8B3B037C08BE'.
    rv_data = rv_data && 'BFD7EAAE0C783EA3FD89E009C8F2FE211F5F0332B43AE567F36A377B52EEA0528F185AADC849A869'.
    rv_data = rv_data && '8CA850FFC10A4064B11F322A63DE7601F39B8B68DEA14C5B4E4411947424922A3B35FCFB85169A18'.
    rv_data = rv_data && '72653667CD1944493572B4EF2E13797D38F5576963F186190404E98E3C0151C7E464EADA79F5FB6F'.
    rv_data = rv_data && '66ECB2525ED96C9B3A10C4A49EB835142CC14A5EA83D27FE7BE2E2F88B4FDFF35D1EF90AAB4A498A'.
    rv_data = rv_data && '5B8C6F55D6A7CD4B529ECDFF318D49D848AA413C9396C5FB1B1320BF9214E87A0EE69B3C953F0068'.
    rv_data = rv_data && '68C7A27E2E2D2DB6ADBBF4ECAC7696F6DB46E9A00BE05416B5C50080353DB987BF37B6752E745B9E'.
    rv_data = rv_data && '9336AA61CDFC6D8C02DB14DC56A3679CD593517364DFBC0C2F561A14C9CC7E0849C30DB20ED6FFF1'.
    rv_data = rv_data && 'A1749AEC19F4E9591894C3EFD5F10F9EB922EC7BD16E417C3F11AEC726D80413365E8189E051BA7A'.
    rv_data = rv_data && '9F68D9E256E8E8A30FC813DC0C22783CE8B2A4A38AB9910DF95BB61CF1D1021BC568BC7B8034F9E9'.
    rv_data = rv_data && 'F9405A15A0FF2B88CC64AA5064D362D86A2854E5F22E78211353AEE9844EC84F36456EFAB4390EBA'.
    rv_data = rv_data && 'CDEB435CF3DC34E9EE653B3ABB59ABD6E86032C5BA4984C88F70B6961D7CE293CFB8A6B6F4006A38'.
    rv_data = rv_data && '70BEC95AEA61F8AEC7155062C391B1F1B8B8ACE2C417C21238C90487589CE90014DFA55DBCD88EA1'.
    rv_data = rv_data && '0CA8650EA1297D21BC36545100EE92F4869DC5A99A569EB2D5D76F32A97F3893F1AACE4533AD7993'.
    rv_data = rv_data && '5A170384B8308AC494019274D043BDA66792D0486E34EEB11A9ABEFC42F542951A3319861CFC2543'.
    rv_data = rv_data && 'CDA385A714EB72F9733EAD876904015A43D992E73805F73BAF72B40C218EEE4AA16315682476837F'.
    rv_data = rv_data && '4CCD9D968A5C3EC92ABA7B3AA98298BBD3ADEDC302D1DFEBBC2436AEC182D11CA74EE1E55FA01DB5'.
    rv_data = rv_data && '7D94BD41BDCABA746CEC6CCEFE969BFB7FF2DB171658A5D9A8B5E06BA672E732B2AAD4616EB3DF7B'.
    rv_data = rv_data && '16389A0F7D365303FDA1917CB858D1926E9D03E040E5AF84C8EE20CBECBF3014DB7D73E45A46BA71'.
    rv_data = rv_data && 'B50ED18F5A78082D644F800B5BFA800B01B4A223E89E6EC7F7C8E75C1BC5768ADCFF018BD7F2E266'.
    rv_data = rv_data && 'A13DA5B60F0CF55B062D8C6B6446737F2C7BE9C3EE0DB7864895812B5F71654F4B28F9361056747A'.
    rv_data = rv_data && 'D4B0E3672E86F0CC20F566A7435E'.
  ENDMETHOD.


  METHOD recorded_outbound.
    rv_data = rv_data && '5353482D322E302D616261700D0A000000E40A14ABABABABABABABABABABABABABABABAB00000059'.
    rv_data = rv_data && '637572766532353531392D7368613235362C6469666669652D68656C6C6D616E2D67726F75703134'.
    rv_data = rv_data && '2D7368613235362C6B65782D7374726963742D632C6B65782D7374726963742D632D763030406F70'.
    rv_data = rv_data && '656E7373682E636F6D0000000C7273612D736861322D3235360000000A6165733132382D63747200'.
    rv_data = rv_data && '00000A6165733132382D6374720000000D686D61632D736861322D3235360000000D686D61632D73'.
    rv_data = rv_data && '6861322D323536000000046E6F6E65000000046E6F6E6500000000000000000000000000ABABABAB'.
    rv_data = rv_data && 'ABABABABABAB0000002C061E00000020E3712D851A0E5D79B831C5E34AB22B41A198171DE209B8B8'.
    rv_data = rv_data && 'FACA23A11C624859ABABABABABAB0000000C0A15ABABABABABABABABABAB31379259D12B901135B9'.
    rv_data = rv_data && 'A2D610BD7CA466B509F8D9F392C9A494924BB74884B7ECB35DE999B741968778C944742F661CF60F'.
    rv_data = rv_data && '76573AB3F6F38F05C7C5D41EACFAFD53CA6786EAD2B8F14B732A1E911072E7BC39C734DF9F4F3AAF'.
    rv_data = rv_data && '3AEE31D013306199D2B4B005144FC1F14DD2327CB4F30688F231CE312A8E41B28D4C7EFD17B01FF6'.
    rv_data = rv_data && '67D4237F57786A5C02915AC654B5E1DFEC7B670455418E558A1708478BE6177DEC40F9CE6EA7DD40'.
    rv_data = rv_data && '927655DEAFCF943C9DB9B4EEED72B9F10D8BD241428FED5DD17952235600CF4AA2AD1F74AF1C3702'.
    rv_data = rv_data && 'BB2D096DABBE10D9AC3A626F697B6B73977E029966BDF20B81A12AC013220ADB103503B53A1CD1B4'.
    rv_data = rv_data && 'A64EB822ED32B3E1893065D267A8DB308238D84FB67415C534A1A68F1079E4473253491225F732D3'.
    rv_data = rv_data && '4A9EF9832D3E931DFC5264FB79F6C588EEA2F5631E08E28F17BBEFB6935A1091D06B4EEF250C45C1'.
    rv_data = rv_data && 'ADC9D935B5E49F4E2F4FB07687238A54AA1EF94742C974D3E6EBE20BD8C55CD6B8374A25AC52'.
  ENDMETHOD.

ENDCLASS.
