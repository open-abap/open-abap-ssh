CLASS zcl_oassh_sha256 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* FIPS 180-4 SHA-256, implemented from scratch on x LENGTH 4 words so it
* runs identically transpiled and on a real ABAP kernel.

    TYPES ty_word TYPE x LENGTH 4.

    CLASS-METHODS hash
      IMPORTING
        iv_data        TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.

    TYPES ty_words TYPE STANDARD TABLE OF ty_word WITH EMPTY KEY.

    CLASS-METHODS pad
      IMPORTING
        iv_data          TYPE xstring
      RETURNING
        VALUE(rv_padded) TYPE xstring.
    CLASS-METHODS process_block
      IMPORTING
        iv_block TYPE xstring
      CHANGING
        ct_h     TYPE ty_words.
    CLASS-METHODS schedule
      IMPORTING
        iv_block      TYPE xstring
      RETURNING
        VALUE(rt_w)   TYPE ty_words.
    CLASS-METHODS h_init
      RETURNING
        VALUE(rt_h) TYPE ty_words.
    CLASS-METHODS k_table
      RETURNING
        VALUE(rt_k) TYPE ty_words.
    CLASS-METHODS add
      IMPORTING
        iv_a         TYPE ty_word
        iv_b         TYPE ty_word
      RETURNING
        VALUE(rv_r)  TYPE ty_word.
    CLASS-METHODS rotr
      IMPORTING
        iv_word     TYPE ty_word
        iv_n        TYPE i
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS shr
      IMPORTING
        iv_word     TYPE ty_word
        iv_n        TYPE i
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS ch
      IMPORTING
        iv_e        TYPE ty_word
        iv_f        TYPE ty_word
        iv_g        TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS maj
      IMPORTING
        iv_a        TYPE ty_word
        iv_b        TYPE ty_word
        iv_c        TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS big_sigma0
      IMPORTING
        iv_word     TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS big_sigma1
      IMPORTING
        iv_word     TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS small_sigma0
      IMPORTING
        iv_word     TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
    CLASS-METHODS small_sigma1
      IMPORTING
        iv_word     TYPE ty_word
      RETURNING
        VALUE(rv_r) TYPE ty_word.
ENDCLASS.



CLASS zcl_oassh_sha256 IMPLEMENTATION.


  METHOD add.
* 32-bit modular addition, computed byte-wise to avoid integer overflow
* and sign issues
    DATA lv_offset TYPE i.
    DATA lv_carry  TYPE i.
    DATA lv_sum    TYPE i.
    DATA lv_byte_a TYPE x LENGTH 1.
    DATA lv_byte_b TYPE x LENGTH 1.

    DO 4 TIMES.
      lv_offset = 4 - sy-index.
      lv_byte_a = iv_a+lv_offset(1).
      lv_byte_b = iv_b+lv_offset(1).
      lv_sum = lv_byte_a + lv_byte_b + lv_carry.
      lv_carry = lv_sum DIV 256.
      lv_sum = lv_sum MOD 256.
      rv_r+lv_offset(1) = lv_sum.
    ENDDO.

  ENDMETHOD.


  METHOD ch.
* Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
    DATA lv_left  TYPE ty_word.
    DATA lv_note  TYPE ty_word.
    DATA lv_right TYPE ty_word.

    lv_left = iv_e BIT-AND iv_f.
    lv_note = BIT-NOT iv_e.
    lv_right = lv_note BIT-AND iv_g.
    rv_r = lv_left BIT-XOR lv_right.

  ENDMETHOD.


  METHOD maj.
* Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    DATA lv_ab TYPE ty_word.
    DATA lv_ac TYPE ty_word.
    DATA lv_bc TYPE ty_word.

    lv_ab = iv_a BIT-AND iv_b.
    lv_ac = iv_a BIT-AND iv_c.
    lv_bc = iv_b BIT-AND iv_c.
    rv_r = lv_ab BIT-XOR lv_ac.
    rv_r = rv_r BIT-XOR lv_bc.

  ENDMETHOD.


  METHOD big_sigma0.
* Sigma0(x) = ROTR2 XOR ROTR13 XOR ROTR22
    rv_r = rotr(
      iv_word = iv_word
      iv_n    = 2 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 13 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 22 ).
  ENDMETHOD.


  METHOD big_sigma1.
* Sigma1(x) = ROTR6 XOR ROTR11 XOR ROTR25
    rv_r = rotr(
      iv_word = iv_word
      iv_n    = 6 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 11 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 25 ).
  ENDMETHOD.


  METHOD small_sigma0.
* sigma0(x) = ROTR7 XOR ROTR18 XOR SHR3
    rv_r = rotr(
      iv_word = iv_word
      iv_n    = 7 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 18 ).
    rv_r = rv_r BIT-XOR shr(
      iv_word = iv_word
      iv_n    = 3 ).
  ENDMETHOD.


  METHOD small_sigma1.
* sigma1(x) = ROTR17 XOR ROTR19 XOR SHR10
    rv_r = rotr(
      iv_word = iv_word
      iv_n    = 17 ).
    rv_r = rv_r BIT-XOR rotr(
      iv_word = iv_word
      iv_n    = 19 ).
    rv_r = rv_r BIT-XOR shr(
      iv_word = iv_word
      iv_n    = 10 ).
  ENDMETHOD.


  METHOD rotr.
* rotate right: result standard bit p = source standard bit (p + n) mod 32.
* ABAP bit position 1 is the MSB, so standard bit p maps to ABAP bit 32 - p
    DATA lv_dst    TYPE i.
    DATA lv_src    TYPE i.
    DATA lv_abap_s TYPE i.
    DATA lv_abap_d TYPE i.
    DATA lv_bit    TYPE c LENGTH 1.

    DO 32 TIMES.
      lv_dst = sy-index - 1.
      lv_src = ( lv_dst + iv_n ) MOD 32.
      lv_abap_s = 32 - lv_src.
      lv_abap_d = 32 - lv_dst.
      GET BIT lv_abap_s OF iv_word INTO lv_bit.
      IF lv_bit = '1'.
        SET BIT lv_abap_d OF rv_r TO 1.
      ENDIF.
    ENDDO.

  ENDMETHOD.


  METHOD shr.
* logical shift right: result standard bit p = source bit p + n, or 0
    DATA lv_dst    TYPE i.
    DATA lv_src    TYPE i.
    DATA lv_abap_s TYPE i.
    DATA lv_abap_d TYPE i.
    DATA lv_bit    TYPE c LENGTH 1.

    DO 32 TIMES.
      lv_dst = sy-index - 1.
      lv_src = lv_dst + iv_n.
      IF lv_src <= 31.
        lv_abap_s = 32 - lv_src.
        lv_abap_d = 32 - lv_dst.
        GET BIT lv_abap_s OF iv_word INTO lv_bit.
        IF lv_bit = '1'.
          SET BIT lv_abap_d OF rv_r TO 1.
        ENDIF.
      ENDIF.
    ENDDO.

  ENDMETHOD.


  METHOD pad.
* FIPS 180-4 5.1.1: append 0x80, then zero bytes, then the 64-bit length
    DATA lv_length  TYPE i.
    DATA lv_bitlen  TYPE int8.
    DATA lv_lenx    TYPE x LENGTH 8.
    DATA lv_one     TYPE x LENGTH 1 VALUE '80'.
    DATA lv_zero    TYPE x LENGTH 1 VALUE '00'.

    rv_padded = iv_data.
    lv_length = xstrlen( iv_data ).
    lv_bitlen = lv_length * 8.

    CONCATENATE rv_padded lv_one INTO rv_padded IN BYTE MODE.

* pad with zeros until the length is 56 mod 64, leaving room for 8 length bytes
    WHILE xstrlen( rv_padded ) MOD 64 <> 56.
      CONCATENATE rv_padded lv_zero INTO rv_padded IN BYTE MODE.
    ENDWHILE.

    lv_lenx = lv_bitlen.
    CONCATENATE rv_padded lv_lenx INTO rv_padded IN BYTE MODE.

  ENDMETHOD.


  METHOD schedule.
* FIPS 180-4 6.2.2: build the 64-entry message schedule (1-based table)
    DATA lv_offset TYPE i.
    DATA lv_word   TYPE ty_word.
    DATA lv_index  TYPE i.

    DO 16 TIMES.
      lv_offset = ( sy-index - 1 ) * 4.
      lv_word = iv_block+lv_offset(4).
      APPEND lv_word TO rt_w.
    ENDDO.

    DO 48 TIMES.
      lv_index = sy-index + 16.
      lv_word = add(
        iv_a = add(
          iv_a = add(
            iv_a = small_sigma1( rt_w[ lv_index - 2 ] )
            iv_b = rt_w[ lv_index - 7 ] )
          iv_b = small_sigma0( rt_w[ lv_index - 15 ] ) )
        iv_b = rt_w[ lv_index - 16 ] ).
      APPEND lv_word TO rt_w.
    ENDDO.

  ENDMETHOD.


  METHOD process_block.
* FIPS 180-4 6.2.2: one 512-bit block compression
    DATA lt_w TYPE ty_words.
    DATA lt_k TYPE ty_words.
    DATA lv_a TYPE ty_word.
    DATA lv_b TYPE ty_word.
    DATA lv_c TYPE ty_word.
    DATA lv_d TYPE ty_word.
    DATA lv_e TYPE ty_word.
    DATA lv_f TYPE ty_word.
    DATA lv_g TYPE ty_word.
    DATA lv_h TYPE ty_word.
    DATA lv_t1 TYPE ty_word.
    DATA lv_t2 TYPE ty_word.
    DATA lv_index TYPE i.

    lt_w = schedule( iv_block ).
    lt_k = k_table( ).

    lv_a = ct_h[ 1 ].
    lv_b = ct_h[ 2 ].
    lv_c = ct_h[ 3 ].
    lv_d = ct_h[ 4 ].
    lv_e = ct_h[ 5 ].
    lv_f = ct_h[ 6 ].
    lv_g = ct_h[ 7 ].
    lv_h = ct_h[ 8 ].

    DO 64 TIMES.
      lv_index = sy-index.
      lv_t1 = add(
        iv_a = add(
          iv_a = add(
            iv_a = add(
              iv_a = lv_h
              iv_b = big_sigma1( lv_e ) )
            iv_b = ch( iv_e = lv_e iv_f = lv_f iv_g = lv_g ) )
          iv_b = lt_k[ lv_index ] )
        iv_b = lt_w[ lv_index ] ).
      lv_t2 = add(
        iv_a = big_sigma0( lv_a )
        iv_b = maj( iv_a = lv_a iv_b = lv_b iv_c = lv_c ) ).

      lv_h = lv_g.
      lv_g = lv_f.
      lv_f = lv_e.
      lv_e = add(
        iv_a = lv_d
        iv_b = lv_t1 ).
      lv_d = lv_c.
      lv_c = lv_b.
      lv_b = lv_a.
      lv_a = add(
        iv_a = lv_t1
        iv_b = lv_t2 ).
    ENDDO.

    ct_h[ 1 ] = add(
      iv_a = ct_h[ 1 ]
      iv_b = lv_a ).
    ct_h[ 2 ] = add(
      iv_a = ct_h[ 2 ]
      iv_b = lv_b ).
    ct_h[ 3 ] = add(
      iv_a = ct_h[ 3 ]
      iv_b = lv_c ).
    ct_h[ 4 ] = add(
      iv_a = ct_h[ 4 ]
      iv_b = lv_d ).
    ct_h[ 5 ] = add(
      iv_a = ct_h[ 5 ]
      iv_b = lv_e ).
    ct_h[ 6 ] = add(
      iv_a = ct_h[ 6 ]
      iv_b = lv_f ).
    ct_h[ 7 ] = add(
      iv_a = ct_h[ 7 ]
      iv_b = lv_g ).
    ct_h[ 8 ] = add(
      iv_a = ct_h[ 8 ]
      iv_b = lv_h ).

  ENDMETHOD.


  METHOD hash.
    DATA lt_h     TYPE ty_words.
    DATA lv_padded TYPE xstring.
    DATA lv_blocks TYPE i.
    DATA lv_offset TYPE i.
    DATA lv_block  TYPE xstring.
    DATA lv_word   TYPE ty_word.

    lt_h = h_init( ).
    lv_padded = pad( iv_data ).
    lv_blocks = xstrlen( lv_padded ) / 64.

    DO lv_blocks TIMES.
      lv_offset = ( sy-index - 1 ) * 64.
      lv_block = lv_padded+lv_offset(64).
      process_block(
        EXPORTING
          iv_block = lv_block
        CHANGING
          ct_h     = lt_h ).
    ENDDO.

    LOOP AT lt_h INTO lv_word.
      CONCATENATE rv_hash lv_word INTO rv_hash IN BYTE MODE.
    ENDLOOP.

  ENDMETHOD.


  METHOD h_init.
    APPEND '6A09E667' TO rt_h.
    APPEND 'BB67AE85' TO rt_h.
    APPEND '3C6EF372' TO rt_h.
    APPEND 'A54FF53A' TO rt_h.
    APPEND '510E527F' TO rt_h.
    APPEND '9B05688C' TO rt_h.
    APPEND '1F83D9AB' TO rt_h.
    APPEND '5BE0CD19' TO rt_h.
  ENDMETHOD.


  METHOD k_table.
    APPEND '428A2F98' TO rt_k.
    APPEND '71374491' TO rt_k.
    APPEND 'B5C0FBCF' TO rt_k.
    APPEND 'E9B5DBA5' TO rt_k.
    APPEND '3956C25B' TO rt_k.
    APPEND '59F111F1' TO rt_k.
    APPEND '923F82A4' TO rt_k.
    APPEND 'AB1C5ED5' TO rt_k.
    APPEND 'D807AA98' TO rt_k.
    APPEND '12835B01' TO rt_k.
    APPEND '243185BE' TO rt_k.
    APPEND '550C7DC3' TO rt_k.
    APPEND '72BE5D74' TO rt_k.
    APPEND '80DEB1FE' TO rt_k.
    APPEND '9BDC06A7' TO rt_k.
    APPEND 'C19BF174' TO rt_k.
    APPEND 'E49B69C1' TO rt_k.
    APPEND 'EFBE4786' TO rt_k.
    APPEND '0FC19DC6' TO rt_k.
    APPEND '240CA1CC' TO rt_k.
    APPEND '2DE92C6F' TO rt_k.
    APPEND '4A7484AA' TO rt_k.
    APPEND '5CB0A9DC' TO rt_k.
    APPEND '76F988DA' TO rt_k.
    APPEND '983E5152' TO rt_k.
    APPEND 'A831C66D' TO rt_k.
    APPEND 'B00327C8' TO rt_k.
    APPEND 'BF597FC7' TO rt_k.
    APPEND 'C6E00BF3' TO rt_k.
    APPEND 'D5A79147' TO rt_k.
    APPEND '06CA6351' TO rt_k.
    APPEND '14292967' TO rt_k.
    APPEND '27B70A85' TO rt_k.
    APPEND '2E1B2138' TO rt_k.
    APPEND '4D2C6DFC' TO rt_k.
    APPEND '53380D13' TO rt_k.
    APPEND '650A7354' TO rt_k.
    APPEND '766A0ABB' TO rt_k.
    APPEND '81C2C92E' TO rt_k.
    APPEND '92722C85' TO rt_k.
    APPEND 'A2BFE8A1' TO rt_k.
    APPEND 'A81A664B' TO rt_k.
    APPEND 'C24B8B70' TO rt_k.
    APPEND 'C76C51A3' TO rt_k.
    APPEND 'D192E819' TO rt_k.
    APPEND 'D6990624' TO rt_k.
    APPEND 'F40E3585' TO rt_k.
    APPEND '106AA070' TO rt_k.
    APPEND '19A4C116' TO rt_k.
    APPEND '1E376C08' TO rt_k.
    APPEND '2748774C' TO rt_k.
    APPEND '34B0BCB5' TO rt_k.
    APPEND '391C0CB3' TO rt_k.
    APPEND '4ED8AA4A' TO rt_k.
    APPEND '5B9CCA4F' TO rt_k.
    APPEND '682E6FF3' TO rt_k.
    APPEND '748F82EE' TO rt_k.
    APPEND '78A5636F' TO rt_k.
    APPEND '84C87814' TO rt_k.
    APPEND '8CC70208' TO rt_k.
    APPEND '90BEFFFA' TO rt_k.
    APPEND 'A4506CEB' TO rt_k.
    APPEND 'BEF9A3F7' TO rt_k.
    APPEND 'C67178F2' TO rt_k.
  ENDMETHOD.
ENDCLASS.
