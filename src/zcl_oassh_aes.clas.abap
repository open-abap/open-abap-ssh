CLASS zcl_oassh_aes DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* AES block cipher (FIPS 197), encrypt direction only. CTR mode uses the
* forward transform for both encryption and decryption, so no inverse
* cipher is implemented. Key length selects AES-128/192/256 (16/24/32
* bytes). Everything runs on x LENGTH 1 bytes so it behaves identically
* transpiled and on a real ABAP kernel.

    TYPES ty_word TYPE x LENGTH 4.
    TYPES ty_words TYPE STANDARD TABLE OF ty_word WITH EMPTY KEY.

* expand_key computes the round-key schedule once; encrypt_block_schedule
* runs the block transform against a precomputed schedule. CTR mode expands
* the key a single time and reuses the schedule for every counter block.
    CLASS-METHODS expand_key
      IMPORTING
        iv_key      TYPE xstring
      RETURNING
        VALUE(rt_w) TYPE ty_words.
    CLASS-METHODS encrypt_block_schedule
      IMPORTING
        it_w            TYPE ty_words
        iv_block        TYPE xstring
      RETURNING
        VALUE(rv_block) TYPE xstring.
    CLASS-METHODS encrypt_block
      IMPORTING
        iv_key          TYPE xstring
        iv_block        TYPE xstring
      RETURNING
        VALUE(rv_block) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.

    TYPES ty_byte TYPE x LENGTH 1.
    TYPES ty_bytes TYPE STANDARD TABLE OF ty_byte WITH EMPTY KEY.

    CLASS-DATA gv_sbox TYPE xstring.

    CLASS-METHODS sbox
      RETURNING
        VALUE(rv_sbox) TYPE xstring.
    CLASS-METHODS xtime
      IMPORTING
        iv_a        TYPE x
      RETURNING
        VALUE(rv_r) TYPE ty_byte.
    CLASS-METHODS rot_word
      IMPORTING
        iv_word        TYPE ty_word
      RETURNING
        VALUE(rv_word) TYPE ty_word.
    CLASS-METHODS sub_word
      IMPORTING
        iv_word        TYPE ty_word
        iv_sbox        TYPE xstring
      RETURNING
        VALUE(rv_word) TYPE ty_word.
    CLASS-METHODS add_round_key
      IMPORTING
        iv_w     TYPE ty_words
        iv_round TYPE i
      CHANGING
        ct_state TYPE ty_bytes.
    CLASS-METHODS sub_bytes
      IMPORTING
        iv_sbox  TYPE xstring
      CHANGING
        ct_state TYPE ty_bytes.
    CLASS-METHODS shift_rows
      CHANGING
        ct_state TYPE ty_bytes.
    CLASS-METHODS mix_columns
      CHANGING
        ct_state TYPE ty_bytes.
ENDCLASS.



CLASS zcl_oassh_aes IMPLEMENTATION.


  METHOD sbox.
* FIPS 197 figure 7, one row (16 bytes) per literal, built once and cached
    CONSTANTS:
      lc_0 TYPE xstring VALUE '637C777BF26B6FC53001672BFED7AB76',
      lc_1 TYPE xstring VALUE 'CA82C97DFA5947F0ADD4A2AF9CA472C0',
      lc_2 TYPE xstring VALUE 'B7FD9326363FF7CC34A5E5F171D83115',
      lc_3 TYPE xstring VALUE '04C723C31896059A071280E2EB27B275',
      lc_4 TYPE xstring VALUE '09832C1A1B6E5AA0523BD6B329E32F84',
      lc_5 TYPE xstring VALUE '53D100ED20FCB15B6ACBBE394A4C58CF',
      lc_6 TYPE xstring VALUE 'D0EFAAFB434D338545F9027F503C9FA8',
      lc_7 TYPE xstring VALUE '51A3408F929D38F5BCB6DA2110FFF3D2',
      lc_8 TYPE xstring VALUE 'CD0C13EC5F974417C4A77E3D645D1973',
      lc_9 TYPE xstring VALUE '60814FDC222A908846EEB814DE5E0BDB',
      lc_a TYPE xstring VALUE 'E0323A0A4906245CC2D3AC629195E479',
      lc_b TYPE xstring VALUE 'E7C8376D8DD54EA96C56F4EA657AAE08',
      lc_c TYPE xstring VALUE 'BA78252E1CA6B4C6E8DD741F4BBD8B8A',
      lc_d TYPE xstring VALUE '703EB5664803F60E613557B986C11D9E',
      lc_e TYPE xstring VALUE 'E1F8981169D98E949B1E87E9CE5528DF',
      lc_f TYPE xstring VALUE '8CA1890DBFE6426841992D0FB054BB16'.

    IF gv_sbox IS INITIAL.
      CONCATENATE lc_0 lc_1 lc_2 lc_3 lc_4 lc_5 lc_6 lc_7
                  lc_8 lc_9 lc_a lc_b lc_c lc_d lc_e lc_f
        INTO gv_sbox IN BYTE MODE.
    ENDIF.
    rv_sbox = gv_sbox.
  ENDMETHOD.


  METHOD xtime.
* multiply by 2 in GF(2^8): left shift, reduce with 0x1B on overflow
    CONSTANTS lc_reduce TYPE x LENGTH 1 VALUE '1B'.
    DATA lv_i TYPE i.

    lv_i = iv_a.
    lv_i = lv_i * 2.
    IF lv_i >= 256.
      lv_i = lv_i - 256.
      rv_r = lv_i.
      rv_r = rv_r BIT-XOR lc_reduce.
    ELSE.
      rv_r = lv_i.
    ENDIF.
  ENDMETHOD.


  METHOD rot_word.
* [a0 a1 a2 a3] -> [a1 a2 a3 a0]
    CONCATENATE iv_word+1(3) iv_word(1) INTO rv_word IN BYTE MODE.
  ENDMETHOD.


  METHOD sub_word.
* apply the S-box to each of the four bytes
    DATA lv_off TYPE i.
    DATA lv_b0  TYPE x LENGTH 1.
    DATA lv_b1  TYPE x LENGTH 1.
    DATA lv_b2  TYPE x LENGTH 1.
    DATA lv_b3  TYPE x LENGTH 1.

    lv_off = iv_word(1).
    lv_b0 = iv_sbox+lv_off(1).
    lv_off = iv_word+1(1).
    lv_b1 = iv_sbox+lv_off(1).
    lv_off = iv_word+2(1).
    lv_b2 = iv_sbox+lv_off(1).
    lv_off = iv_word+3(1).
    lv_b3 = iv_sbox+lv_off(1).

    CONCATENATE lv_b0 lv_b1 lv_b2 lv_b3 INTO rv_word IN BYTE MODE.
  ENDMETHOD.


  METHOD expand_key.
* FIPS 197 section 5.2 key expansion
    DATA lv_sbox  TYPE xstring.
    DATA lv_nk    TYPE i.
    DATA lv_nr    TYPE i.
    DATA lv_total TYPE i.
    DATA lv_i     TYPE i.
    DATA lv_off   TYPE i.
    DATA lv_word  TYPE ty_word.
    DATA lv_temp  TYPE ty_word.
    DATA lv_prev  TYPE ty_word.
    DATA lv_rcon  TYPE x LENGTH 1 VALUE '01'.
    DATA lv_b0    TYPE x LENGTH 1.

    lv_sbox = sbox( ).
    lv_nk = xstrlen( iv_key ) / 4.
    lv_nr = lv_nk + 6.
    lv_total = 4 * ( lv_nr + 1 ).

    DO lv_nk TIMES.
      lv_off = ( sy-index - 1 ) * 4.
      lv_word = iv_key+lv_off(4).
      APPEND lv_word TO rt_w.
    ENDDO.

    lv_i = lv_nk.
    WHILE lv_i < lv_total.
      lv_temp = rt_w[ lv_i ].
      IF lv_i MOD lv_nk = 0.
        lv_temp = rot_word( lv_temp ).
        lv_temp = sub_word(
          iv_word = lv_temp
          iv_sbox = lv_sbox ).
        lv_b0 = lv_temp(1) BIT-XOR lv_rcon.
        CONCATENATE lv_b0 lv_temp+1(3) INTO lv_temp IN BYTE MODE.
        lv_rcon = xtime( lv_rcon ).
      ELSEIF lv_nk > 6 AND lv_i MOD lv_nk = 4.
        lv_temp = sub_word(
          iv_word = lv_temp
          iv_sbox = lv_sbox ).
      ENDIF.
      lv_prev = rt_w[ lv_i - lv_nk + 1 ].
      lv_word = lv_prev BIT-XOR lv_temp.
      APPEND lv_word TO rt_w.
      lv_i = lv_i + 1.
    ENDWHILE.
  ENDMETHOD.


  METHOD add_round_key.
* XOR the four round-key words (one per column) into the state
    DATA lv_c    TYPE i.
    DATA lv_r    TYPE i.
    DATA lv_pos  TYPE i.
    DATA lv_widx TYPE i.
    DATA lv_word TYPE ty_word.
    DATA lv_kb   TYPE x LENGTH 1.
    DATA lv_sb   TYPE x LENGTH 1.

    DO 4 TIMES.
      lv_c = sy-index - 1.
      lv_widx = 4 * iv_round + lv_c + 1.
      lv_word = iv_w[ lv_widx ].
      DO 4 TIMES.
        lv_r = sy-index - 1.
        lv_pos = 4 * lv_c + lv_r + 1.
        lv_kb = lv_word+lv_r(1).
        lv_sb = ct_state[ lv_pos ].
        ct_state[ lv_pos ] = lv_sb BIT-XOR lv_kb.
      ENDDO.
    ENDDO.
  ENDMETHOD.


  METHOD sub_bytes.
* replace every state byte with its S-box value
    DATA lv_i   TYPE i.
    DATA lv_off TYPE i.
    DATA lv_b   TYPE x LENGTH 1.

    DO 16 TIMES.
      lv_i = sy-index.
      lv_b = ct_state[ lv_i ].
      lv_off = lv_b.
      ct_state[ lv_i ] = iv_sbox+lv_off(1).
    ENDDO.
  ENDMETHOD.


  METHOD shift_rows.
* the state is stored column-major; row r is rotated left by r
    DATA lt_new TYPE ty_bytes.
    DATA lv_r   TYPE i.
    DATA lv_c   TYPE i.
    DATA lv_sc  TYPE i.
    DATA lv_src TYPE i.
    DATA lv_dst TYPE i.

    lt_new = ct_state.
    DO 4 TIMES.
      lv_r = sy-index - 1.
      DO 4 TIMES.
        lv_c = sy-index - 1.
        lv_sc = ( lv_c + lv_r ) MOD 4.
        lv_src = 4 * lv_sc + lv_r + 1.
        lv_dst = 4 * lv_c + lv_r + 1.
        lt_new[ lv_dst ] = ct_state[ lv_src ].
      ENDDO.
    ENDDO.
    ct_state = lt_new.
  ENDMETHOD.


  METHOD mix_columns.
* FIPS 197 section 5.1.3: multiply each column by the fixed polynomial
    DATA lv_c    TYPE i.
    DATA lv_base TYPE i.
    DATA lv_s0   TYPE x LENGTH 1.
    DATA lv_s1   TYPE x LENGTH 1.
    DATA lv_s2   TYPE x LENGTH 1.
    DATA lv_s3   TYPE x LENGTH 1.
    DATA lv_o0   TYPE x LENGTH 1.
    DATA lv_o1   TYPE x LENGTH 1.
    DATA lv_o2   TYPE x LENGTH 1.
    DATA lv_o3   TYPE x LENGTH 1.

    DO 4 TIMES.
      lv_c = sy-index - 1.
      lv_base = 4 * lv_c.
      lv_s0 = ct_state[ lv_base + 1 ].
      lv_s1 = ct_state[ lv_base + 2 ].
      lv_s2 = ct_state[ lv_base + 3 ].
      lv_s3 = ct_state[ lv_base + 4 ].

* out0 = 2*s0 ^ 3*s1 ^ s2 ^ s3
      lv_o0 = xtime( lv_s0 ).
      lv_o0 = lv_o0 BIT-XOR xtime( lv_s1 ).
      lv_o0 = lv_o0 BIT-XOR lv_s1.
      lv_o0 = lv_o0 BIT-XOR lv_s2.
      lv_o0 = lv_o0 BIT-XOR lv_s3.
* out1 = s0 ^ 2*s1 ^ 3*s2 ^ s3
      lv_o1 = lv_s0.
      lv_o1 = lv_o1 BIT-XOR xtime( lv_s1 ).
      lv_o1 = lv_o1 BIT-XOR xtime( lv_s2 ).
      lv_o1 = lv_o1 BIT-XOR lv_s2.
      lv_o1 = lv_o1 BIT-XOR lv_s3.
* out2 = s0 ^ s1 ^ 2*s2 ^ 3*s3
      lv_o2 = lv_s0.
      lv_o2 = lv_o2 BIT-XOR lv_s1.
      lv_o2 = lv_o2 BIT-XOR xtime( lv_s2 ).
      lv_o2 = lv_o2 BIT-XOR xtime( lv_s3 ).
      lv_o2 = lv_o2 BIT-XOR lv_s3.
* out3 = 3*s0 ^ s1 ^ s2 ^ 2*s3
      lv_o3 = xtime( lv_s0 ).
      lv_o3 = lv_o3 BIT-XOR lv_s0.
      lv_o3 = lv_o3 BIT-XOR lv_s1.
      lv_o3 = lv_o3 BIT-XOR lv_s2.
      lv_o3 = lv_o3 BIT-XOR xtime( lv_s3 ).

      ct_state[ lv_base + 1 ] = lv_o0.
      ct_state[ lv_base + 2 ] = lv_o1.
      ct_state[ lv_base + 3 ] = lv_o2.
      ct_state[ lv_base + 4 ] = lv_o3.
    ENDDO.
  ENDMETHOD.


  METHOD encrypt_block.
    rv_block = encrypt_block_schedule(
      it_w     = expand_key( iv_key )
      iv_block = iv_block ).
  ENDMETHOD.


  METHOD encrypt_block_schedule.
    DATA lt_state TYPE ty_bytes.
    DATA lv_sbox  TYPE xstring.
    DATA lv_nr    TYPE i.
    DATA lv_round TYPE i.
    DATA lv_off   TYPE i.
    DATA lv_byte  TYPE x LENGTH 1.

    lv_sbox = sbox( ).
* the schedule holds 4 words per round plus the initial round key
    lv_nr = lines( it_w ) / 4 - 1.

    DO 16 TIMES.
      lv_off = sy-index - 1.
      lv_byte = iv_block+lv_off(1).
      APPEND lv_byte TO lt_state.
    ENDDO.

    add_round_key(
      EXPORTING
        iv_w     = it_w
        iv_round = 0
      CHANGING
        ct_state = lt_state ).

    lv_round = 1.
    WHILE lv_round < lv_nr.
      sub_bytes(
        EXPORTING
          iv_sbox  = lv_sbox
        CHANGING
          ct_state = lt_state ).
      shift_rows( CHANGING ct_state = lt_state ).
      mix_columns( CHANGING ct_state = lt_state ).
      add_round_key(
        EXPORTING
          iv_w     = it_w
          iv_round = lv_round
        CHANGING
          ct_state = lt_state ).
      lv_round = lv_round + 1.
    ENDWHILE.

    sub_bytes(
      EXPORTING
        iv_sbox  = lv_sbox
      CHANGING
        ct_state = lt_state ).
    shift_rows( CHANGING ct_state = lt_state ).
    add_round_key(
      EXPORTING
        iv_w     = it_w
        iv_round = lv_nr
      CHANGING
        ct_state = lt_state ).

    LOOP AT lt_state INTO lv_byte.
      CONCATENATE rv_block lv_byte INTO rv_block IN BYTE MODE.
    ENDLOOP.
  ENDMETHOD.
ENDCLASS.
