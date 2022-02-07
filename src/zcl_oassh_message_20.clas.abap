CLASS zcl_oassh_message_20 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.

    DATA: BEGIN OF ms_data,
            message_id                    TYPE x LENGTH 1,
            cookie                        TYPE x LENGTH 16,
            kex_algorithms                TYPE string_table,
            server_host_key_algorithms    TYPE string_table,
            encryption_algorithms_c_to_s  TYPE string_table,
            encryption_algorithms_s_to_c  TYPE string_table,
            mac_algorithms_c_to_s         TYPE string_table,
            mac_algorithms_s_to_c         TYPE string_table,
            compression_algorithms_c_to_s TYPE string_table,
            compression_algorithms_s_to_c TYPE string_table,
            languages_c_to_s              TYPE string_table,
            languages_s_to_c              TYPE string_table,
            first_kex_packet_follows      TYPE abap_bool,
            reserved                      TYPE i,
          END OF ms_data.

    METHODS get_raw RETURNING VALUE(rv_raw) TYPE xstring.
    METHODS set_raw IMPORTING iv_raw TYPE xstring.
    METHODS get_data RETURNING VALUE(rs_data) LIKE ms_data.
    METHODS set_data IMPORTING is_data LIKE ms_data.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS ZCL_OASSH_MESSAGE_20 IMPLEMENTATION.


  METHOD get_data.
    rs_data = ms_data.
  ENDMETHOD.


  METHOD get_raw.

    DATA lo_stream TYPE REF TO zcl_oassh_stream.

    CREATE OBJECT lo_stream.

  ENDMETHOD.


  METHOD set_data.
    ms_data = is_data.
  ENDMETHOD.


  METHOD set_raw.
* todo
  ENDMETHOD.
ENDCLASS.
