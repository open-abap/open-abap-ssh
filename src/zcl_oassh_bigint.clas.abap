CLASS zcl_oassh_bigint DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.

* arbitrary-precision non-negative integers, stored big-endian and
* normalised (no leading zero bytes; zero is the empty xstring). Provides
* the arithmetic needed for RSA verification and Diffie-Hellman.

    CLASS-METHODS add
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS subtract
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS compare
      IMPORTING
        iv_a          TYPE xstring
        iv_b          TYPE xstring
      RETURNING
        VALUE(rv_cmp) TYPE i.
    CLASS-METHODS multiply
      IMPORTING
        iv_a        TYPE xstring
        iv_b        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS modulo
      IMPORTING
        iv_a        TYPE xstring
        iv_m        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS mod_pow
      IMPORTING
        iv_base     TYPE xstring
        iv_exp      TYPE xstring
        iv_m        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
  PROTECTED SECTION.
  PRIVATE SECTION.

    CLASS-METHODS normalize
      IMPORTING
        iv_x        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
ENDCLASS.



CLASS zcl_oassh_bigint IMPLEMENTATION.


  METHOD normalize.
* strip leading zero bytes; zero collapses to the empty xstring
    rv_r = iv_x.
    WHILE xstrlen( rv_r ) > 0 AND rv_r(1) = '00'.
      rv_r = rv_r+1.
    ENDWHILE.
  ENDMETHOD.


  METHOD compare.
* -1 if a < b, 0 if a = b, 1 if a > b
    DATA lv_a      TYPE xstring.
    DATA lv_b      TYPE xstring.
    DATA lv_offset TYPE i.
    DATA lv_byte_a TYPE x LENGTH 1.
    DATA lv_byte_b TYPE x LENGTH 1.
    DATA lv_int_a  TYPE i.
    DATA lv_int_b  TYPE i.

    lv_a = normalize( iv_a ).
    lv_b = normalize( iv_b ).

    IF xstrlen( lv_a ) > xstrlen( lv_b ).
      rv_cmp = 1.
      RETURN.
    ELSEIF xstrlen( lv_a ) < xstrlen( lv_b ).
      rv_cmp = -1.
      RETURN.
    ENDIF.

* compare byte magnitudes as integers; a direct x-to-x comparison is
* signed in the transpiler and mishandles bytes >= 0x80 (see ANORMALIES.md)
    DO xstrlen( lv_a ) TIMES.
      lv_offset = sy-index - 1.
      lv_byte_a = lv_a+lv_offset(1).
      lv_byte_b = lv_b+lv_offset(1).
      lv_int_a = lv_byte_a.
      lv_int_b = lv_byte_b.
      IF lv_int_a > lv_int_b.
        rv_cmp = 1.
        RETURN.
      ELSEIF lv_int_a < lv_int_b.
        rv_cmp = -1.
        RETURN.
      ENDIF.
    ENDDO.

    rv_cmp = 0.
  ENDMETHOD.


  METHOD add.
    DATA lv_len_a  TYPE i.
    DATA lv_len_b  TYPE i.
    DATA lv_max    TYPE i.
    DATA lv_pos    TYPE i.
    DATA lv_off    TYPE i.
    DATA lv_carry  TYPE i.
    DATA lv_sum    TYPE i.
    DATA lv_byte_a TYPE x LENGTH 1.
    DATA lv_byte_b TYPE x LENGTH 1.
    DATA lv_out    TYPE x LENGTH 1.

    lv_len_a = xstrlen( iv_a ).
    lv_len_b = xstrlen( iv_b ).
    lv_max = lv_len_a.
    IF lv_len_b > lv_max.
      lv_max = lv_len_b.
    ENDIF.

    lv_carry = 0.
    DO lv_max TIMES.
      lv_pos = sy-index.
      lv_byte_a = '00'.
      lv_off = lv_len_a - lv_pos.
      IF lv_off >= 0.
        lv_byte_a = iv_a+lv_off(1).
      ENDIF.
      lv_byte_b = '00'.
      lv_off = lv_len_b - lv_pos.
      IF lv_off >= 0.
        lv_byte_b = iv_b+lv_off(1).
      ENDIF.
      lv_sum = lv_byte_a + lv_byte_b + lv_carry.
      lv_carry = lv_sum DIV 256.
      lv_out = lv_sum MOD 256.
      CONCATENATE lv_out rv_r INTO rv_r IN BYTE MODE.
    ENDDO.

    IF lv_carry > 0.
      lv_out = lv_carry.
      CONCATENATE lv_out rv_r INTO rv_r IN BYTE MODE.
    ENDIF.

    rv_r = normalize( rv_r ).
  ENDMETHOD.


  METHOD subtract.
* requires a >= b
    DATA lv_len_a  TYPE i.
    DATA lv_len_b  TYPE i.
    DATA lv_pos    TYPE i.
    DATA lv_off    TYPE i.
    DATA lv_borrow TYPE i.
    DATA lv_diff   TYPE i.
    DATA lv_byte_a TYPE x LENGTH 1.
    DATA lv_byte_b TYPE x LENGTH 1.
    DATA lv_out    TYPE x LENGTH 1.

    ASSERT compare(
      iv_a = iv_a
      iv_b = iv_b ) >= 0.

    lv_len_a = xstrlen( iv_a ).
    lv_len_b = xstrlen( iv_b ).

    lv_borrow = 0.
    DO lv_len_a TIMES.
      lv_pos = sy-index.
      lv_off = lv_len_a - lv_pos.
      lv_byte_a = iv_a+lv_off(1).
      lv_byte_b = '00'.
      lv_off = lv_len_b - lv_pos.
      IF lv_off >= 0.
        lv_byte_b = iv_b+lv_off(1).
      ENDIF.
      lv_diff = lv_byte_a - lv_byte_b - lv_borrow.
      IF lv_diff < 0.
        lv_diff = lv_diff + 256.
        lv_borrow = 1.
      ELSE.
        lv_borrow = 0.
      ENDIF.
      lv_out = lv_diff.
      CONCATENATE lv_out rv_r INTO rv_r IN BYTE MODE.
    ENDDO.

    rv_r = normalize( rv_r ).
  ENDMETHOD.


  METHOD multiply.
* schoolbook multiplication with per-column accumulation in integers
    DATA lv_len_a  TYPE i.
    DATA lv_len_b  TYPE i.
    DATA lv_size   TYPE i.
    DATA lt_acc    TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    DATA lv_i      TYPE i.
    DATA lv_off_a  TYPE i.
    DATA lv_off_b  TYPE i.
    DATA lv_pos    TYPE i.
    DATA lv_byte_a TYPE x LENGTH 1.
    DATA lv_byte_b TYPE x LENGTH 1.
    DATA lv_int_a  TYPE i.
    DATA lv_int_b  TYPE i.
    DATA lv_carry  TYPE i.
    DATA lv_val    TYPE i.
    DATA lv_out    TYPE x LENGTH 1.

    lv_len_a = xstrlen( iv_a ).
    lv_len_b = xstrlen( iv_b ).
    IF lv_len_a = 0 OR lv_len_b = 0.
      RETURN.
    ENDIF.

    lv_size = lv_len_a + lv_len_b.
    DO lv_size TIMES.
      APPEND 0 TO lt_acc.
    ENDDO.

    DO lv_len_a TIMES.
      lv_i = sy-index - 1.
      lv_off_a = lv_len_a - 1 - lv_i.
      lv_byte_a = iv_a+lv_off_a(1).
      lv_int_a = lv_byte_a.
      DO lv_len_b TIMES.
        lv_off_b = lv_len_b - sy-index.
        lv_byte_b = iv_b+lv_off_b(1).
        lv_int_b = lv_byte_b.
        lv_pos = lv_i + sy-index.
        lt_acc[ lv_pos ] = lt_acc[ lv_pos ] + lv_int_a * lv_int_b.
      ENDDO.
    ENDDO.

    lv_carry = 0.
    DO lv_size TIMES.
      lv_pos = sy-index.
      lv_val = lt_acc[ lv_pos ] + lv_carry.
      lv_carry = lv_val DIV 256.
      lv_out = lv_val MOD 256.
      CONCATENATE lv_out rv_r INTO rv_r IN BYTE MODE.
    ENDDO.

    rv_r = normalize( rv_r ).
  ENDMETHOD.


  METHOD modulo.
* remainder via binary long division, most significant bit first
    DATA lv_nbits     TYPE i.
    DATA lv_bitidx    TYPE i.
    DATA lv_byteoff   TYPE i.
    DATA lv_bitinbyte TYPE i.
    DATA lv_bytex     TYPE x LENGTH 1.
    DATA lv_bit       TYPE c LENGTH 1.

    lv_nbits = xstrlen( iv_a ) * 8.
    DO lv_nbits TIMES.
      lv_bitidx = sy-index - 1.
      lv_byteoff = lv_bitidx DIV 8.
      lv_bitinbyte = lv_bitidx MOD 8 + 1.
      lv_bytex = iv_a+lv_byteoff(1).
      GET BIT lv_bitinbyte OF lv_bytex INTO lv_bit.

* shift the running remainder left by one bit, then bring in the next bit
      rv_r = add(
        iv_a = rv_r
        iv_b = rv_r ).
      IF lv_bit = '1'.
        rv_r = add(
          iv_a = rv_r
          iv_b = '01' ).
      ENDIF.
      IF compare(
          iv_a = rv_r
          iv_b = iv_m ) >= 0.
        rv_r = subtract(
          iv_a = rv_r
          iv_b = iv_m ).
      ENDIF.
    ENDDO.

    rv_r = normalize( rv_r ).
  ENDMETHOD.


  METHOD mod_pow.
* square-and-multiply, most significant bit of the exponent first
    DATA lv_base      TYPE xstring.
    DATA lv_nbits     TYPE i.
    DATA lv_bitidx    TYPE i.
    DATA lv_byteoff   TYPE i.
    DATA lv_bitinbyte TYPE i.
    DATA lv_bytex     TYPE x LENGTH 1.
    DATA lv_bit       TYPE c LENGTH 1.

    lv_base = modulo(
      iv_a = iv_base
      iv_m = iv_m ).
    rv_r = '01'.

    lv_nbits = xstrlen( iv_exp ) * 8.
    DO lv_nbits TIMES.
      lv_bitidx = sy-index - 1.
      lv_byteoff = lv_bitidx DIV 8.
      lv_bitinbyte = lv_bitidx MOD 8 + 1.
      lv_bytex = iv_exp+lv_byteoff(1).
      GET BIT lv_bitinbyte OF lv_bytex INTO lv_bit.

      rv_r = modulo(
        iv_a = multiply(
          iv_a = rv_r
          iv_b = rv_r )
        iv_m = iv_m ).
      IF lv_bit = '1'.
        rv_r = modulo(
          iv_a = multiply(
            iv_a = rv_r
            iv_b = lv_base )
          iv_m = iv_m ).
      ENDIF.
    ENDDO.

    rv_r = normalize( rv_r ).
  ENDMETHOD.
ENDCLASS.
