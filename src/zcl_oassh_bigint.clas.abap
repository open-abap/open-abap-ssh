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

* Montgomery arithmetic for the odd-modulus fast path (RSA). Numbers are
* held as little-endian base-2^15 integer limbs; two limbs multiply and
* accumulate below ABAP's signed 32-bit ceiling.
    TYPES ty_limbs TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    CONSTANTS c_base TYPE i VALUE 32768.

    CLASS-METHODS normalize
      IMPORTING
        iv_x        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS mod_pow_binary
      IMPORTING
        iv_base     TYPE xstring
        iv_exp      TYPE xstring
        iv_m        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS mod_pow_odd
      IMPORTING
        iv_base     TYPE xstring
        iv_exp      TYPE xstring
        iv_m        TYPE xstring
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS to_limbs
      IMPORTING
        iv_x            TYPE xstring
      RETURNING
        VALUE(rt_limbs) TYPE ty_limbs.
    CLASS-METHODS from_limbs
      IMPORTING
        it_limbs    TYPE ty_limbs
      RETURNING
        VALUE(rv_r) TYPE xstring.
    CLASS-METHODS mont_n0inv
      IMPORTING
        iv_m0          TYPE i
      RETURNING
        VALUE(rv_n0inv) TYPE i.
    CLASS-METHODS mont_mul
      IMPORTING
        it_a            TYPE ty_limbs
        it_b            TYPE ty_limbs
        it_m            TYPE ty_limbs
        iv_n0inv        TYPE i
        iv_n            TYPE i
      RETURNING
        VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS double_mod
      IMPORTING
        it_value         TYPE ty_limbs
        it_m             TYPE ty_limbs
      RETURNING
        VALUE(rt_result) TYPE ty_limbs.
    CLASS-METHODS limb_ge
      IMPORTING
        it_a         TYPE ty_limbs
        it_b         TYPE ty_limbs
      RETURNING
        VALUE(rv_ge) TYPE abap_bool.
    CLASS-METHODS limb_sub
      IMPORTING
        it_a             TYPE ty_limbs
        it_b             TYPE ty_limbs
      RETURNING
        VALUE(rt_result) TYPE ty_limbs.
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
* An odd modulus (always the case for RSA) uses Montgomery reduction, which
* replaces the bit-by-bit binary long division of the generic path with
* integer-limb arithmetic. Even moduli keep the generic algorithm.
    DATA lv_m    TYPE xstring.
    DATA lv_off  TYPE i.
    DATA lv_last TYPE x LENGTH 1.
    DATA lv_bit  TYPE c LENGTH 1.

    lv_m = normalize( iv_m ).
    ASSERT xstrlen( lv_m ) > 0.
    lv_off = xstrlen( lv_m ) - 1.
    lv_last = lv_m+lv_off(1).
    GET BIT 8 OF lv_last INTO lv_bit.
    IF lv_bit = '1'.
      rv_r = mod_pow_odd(
        iv_base = iv_base
        iv_exp  = iv_exp
        iv_m    = lv_m ).
    ELSE.
      rv_r = mod_pow_binary(
        iv_base = iv_base
        iv_exp  = iv_exp
        iv_m    = lv_m ).
    ENDIF.
  ENDMETHOD.


  METHOD mod_pow_binary.
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


  METHOD mod_pow_odd.
    DATA lt_m       TYPE ty_limbs.
    DATA lt_r2      TYPE ty_limbs.
    DATA lt_base    TYPE ty_limbs.
    DATA lt_one     TYPE ty_limbs.
    DATA lt_result  TYPE ty_limbs.
    DATA lv_n       TYPE i.
    DATA lv_n0inv   TYPE i.
    DATA lv_reduced TYPE xstring.
    DATA lv_nbits   TYPE i.
    DATA lv_started TYPE abap_bool.
    DATA lv_bitidx  TYPE i.
    DATA lv_byteoff TYPE i.
    DATA lv_bitin   TYPE i.
    DATA lv_bytex   TYPE x LENGTH 1.
    DATA lv_bit     TYPE c LENGTH 1.

    lt_m = to_limbs( iv_m ).
    lv_n = lines( lt_m ).
    lv_n0inv = mont_n0inv( lt_m[ 1 ] ).

* R^2 mod m, where R = 2^(15n), by 2*15*n doublings of 1
    APPEND 1 TO lt_r2.
    DO 2 * 15 * lv_n TIMES.
      lt_r2 = double_mod(
        it_value = lt_r2
        it_m     = lt_m ).
    ENDDO.
    WHILE lines( lt_r2 ) < lv_n.
      APPEND 0 TO lt_r2.
    ENDWHILE.

* base, reduced into n limbs first if it is wider than the modulus
    lt_base = to_limbs( iv_base ).
    IF lines( lt_base ) > lv_n.
      lv_reduced = modulo(
        iv_a = iv_base
        iv_m = iv_m ).
      lt_base = to_limbs( lv_reduced ).
    ENDIF.
    WHILE lines( lt_base ) < lv_n.
      APPEND 0 TO lt_base.
    ENDWHILE.

    DO lv_n TIMES.
      APPEND 0 TO lt_one.
    ENDDO.
    lt_one[ 1 ] = 1.

* into the Montgomery domain: base * R, and R (the domain's 1)
    lt_base = mont_mul(
      it_a     = lt_base
      it_b     = lt_r2
      it_m     = lt_m
      iv_n0inv = lv_n0inv
      iv_n     = lv_n ).
    lt_result = mont_mul(
      it_a     = lt_one
      it_b     = lt_r2
      it_m     = lt_m
      iv_n0inv = lv_n0inv
      iv_n     = lv_n ).

* square-and-multiply, most significant exponent bit first, skipping the
* leading zero bits so a small exponent (e.g. 65537) costs only its width
    lv_nbits = xstrlen( iv_exp ) * 8.
    DO lv_nbits TIMES.
      lv_bitidx = sy-index - 1.
      lv_byteoff = lv_bitidx DIV 8.
      lv_bitin = lv_bitidx MOD 8 + 1.
      lv_bytex = iv_exp+lv_byteoff(1).
      GET BIT lv_bitin OF lv_bytex INTO lv_bit.
      IF lv_started = abap_false.
        IF lv_bit = '0'.
          CONTINUE.
        ENDIF.
        lv_started = abap_true.
      ENDIF.
      lt_result = mont_mul(
        it_a     = lt_result
        it_b     = lt_result
        it_m     = lt_m
        iv_n0inv = lv_n0inv
        iv_n     = lv_n ).
      IF lv_bit = '1'.
        lt_result = mont_mul(
          it_a     = lt_result
          it_b     = lt_base
          it_m     = lt_m
          iv_n0inv = lv_n0inv
          iv_n     = lv_n ).
      ENDIF.
    ENDDO.

* out of the Montgomery domain (multiply by 1)
    lt_result = mont_mul(
      it_a     = lt_result
      it_b     = lt_one
      it_m     = lt_m
      iv_n0inv = lv_n0inv
      iv_n     = lv_n ).
    rv_r = from_limbs( lt_result ).
  ENDMETHOD.


  METHOD mont_n0inv.
* -m0^-1 mod 2^15 by Hensel lifting; five Newton steps cover 2^15
    DATA lv_inv TYPE i VALUE 1.
    DATA lv_t   TYPE i.

    DO 5 TIMES.
      lv_t = ( iv_m0 * lv_inv ) MOD c_base.
      lv_t = 2 - lv_t.
      lv_t = lv_t MOD c_base.
      IF lv_t < 0.
        lv_t = lv_t + c_base.
      ENDIF.
      lv_inv = ( lv_inv * lv_t ) MOD c_base.
    ENDDO.
    rv_n0inv = ( c_base - lv_inv ) MOD c_base.
  ENDMETHOD.


  METHOD mont_mul.
* CIOS Montgomery product: rt = a * b * R^-1 mod m, all limbs base 2^15
    DATA lt_a     TYPE ty_limbs.
    DATA lt_b     TYPE ty_limbs.
    DATA lt_t     TYPE ty_limbs.
    DATA lv_i     TYPE i.
    DATA lv_j     TYPE i.
    DATA lv_pos   TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.
    DATA lv_mm    TYPE i.

    lt_a = it_a.
    WHILE lines( lt_a ) < iv_n.
      APPEND 0 TO lt_a.
    ENDWHILE.
    lt_b = it_b.
    WHILE lines( lt_b ) < iv_n.
      APPEND 0 TO lt_b.
    ENDWHILE.
    DO iv_n * 2 + 2 TIMES.
      APPEND 0 TO lt_t.
    ENDDO.

    DO iv_n TIMES.
      lv_i = sy-index - 1.
      lv_carry = 0.
      DO iv_n TIMES.
        lv_j = sy-index - 1.
        lv_pos = lv_i + lv_j + 1.
        lv_value = lt_t[ lv_pos ] + lt_a[ lv_i + 1 ] * lt_b[ lv_j + 1 ] + lv_carry.
        lt_t[ lv_pos ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      lv_pos = lv_i + iv_n + 1.
      WHILE lv_carry > 0.
        lv_value = lt_t[ lv_pos ] + lv_carry.
        lt_t[ lv_pos ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
        lv_pos = lv_pos + 1.
      ENDWHILE.
    ENDDO.

    DO iv_n TIMES.
      lv_i = sy-index - 1.
      lv_mm = ( lt_t[ lv_i + 1 ] * iv_n0inv ) MOD c_base.
      lv_carry = 0.
      DO iv_n TIMES.
        lv_j = sy-index - 1.
        lv_pos = lv_i + lv_j + 1.
        lv_value = lt_t[ lv_pos ] + lv_mm * it_m[ lv_j + 1 ] + lv_carry.
        lt_t[ lv_pos ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
      ENDDO.
      lv_pos = lv_i + iv_n + 1.
      WHILE lv_carry > 0.
        lv_value = lt_t[ lv_pos ] + lv_carry.
        lt_t[ lv_pos ] = lv_value MOD c_base.
        lv_carry = lv_value DIV c_base.
        lv_pos = lv_pos + 1.
      ENDWHILE.
    ENDDO.

* the reduced result occupies the high half, t[n+1 .. 2n+1]
    DO iv_n + 1 TIMES.
      APPEND lt_t[ iv_n + sy-index ] TO rt_result.
    ENDDO.
    IF limb_ge(
        it_a = rt_result
        it_b = it_m ) = abap_true.
      rt_result = limb_sub(
        it_a = rt_result
        it_b = it_m ).
    ENDIF.
    WHILE lines( rt_result ) < iv_n.
      APPEND 0 TO rt_result.
    ENDWHILE.
  ENDMETHOD.


  METHOD double_mod.
    DATA lv_index TYPE i.
    DATA lv_carry TYPE i.
    DATA lv_value TYPE i.

    DO lines( it_value ) TIMES.
      lv_index = sy-index.
      lv_value = it_value[ lv_index ] * 2 + lv_carry.
      APPEND lv_value MOD c_base TO rt_result.
      lv_carry = lv_value DIV c_base.
    ENDDO.
    IF lv_carry > 0.
      APPEND lv_carry TO rt_result.
    ENDIF.
    IF limb_ge(
        it_a = rt_result
        it_b = it_m ) = abap_true.
      rt_result = limb_sub(
        it_a = rt_result
        it_b = it_m ).
    ENDIF.
  ENDMETHOD.


  METHOD limb_ge.
    DATA lv_max TYPE i.
    DATA lv_la  TYPE i.
    DATA lv_lb  TYPE i.
    DATA lv_i   TYPE i.
    DATA lv_va  TYPE i.
    DATA lv_vb  TYPE i.

    lv_la = lines( it_a ).
    lv_lb = lines( it_b ).
    lv_max = lv_la.
    IF lv_lb > lv_max.
      lv_max = lv_lb.
    ENDIF.
    lv_i = lv_max.
    WHILE lv_i > 0.
      lv_va = 0.
      IF lv_i <= lv_la.
        lv_va = it_a[ lv_i ].
      ENDIF.
      lv_vb = 0.
      IF lv_i <= lv_lb.
        lv_vb = it_b[ lv_i ].
      ENDIF.
      IF lv_va > lv_vb.
        rv_ge = abap_true.
        RETURN.
      ELSEIF lv_va < lv_vb.
        rv_ge = abap_false.
        RETURN.
      ENDIF.
      lv_i = lv_i - 1.
    ENDWHILE.
    rv_ge = abap_true.
  ENDMETHOD.


  METHOD limb_sub.
* it_a - it_b, requires it_a >= it_b; both little-endian
    DATA lv_i      TYPE i.
    DATA lv_lb     TYPE i.
    DATA lv_borrow TYPE i.
    DATA lv_vb     TYPE i.
    DATA lv_value  TYPE i.

    lv_lb = lines( it_b ).
    DO lines( it_a ) TIMES.
      lv_i = sy-index.
      lv_vb = 0.
      IF lv_i <= lv_lb.
        lv_vb = it_b[ lv_i ].
      ENDIF.
      lv_value = it_a[ lv_i ] - lv_vb - lv_borrow.
      IF lv_value < 0.
        lv_value = lv_value + c_base.
        lv_borrow = 1.
      ELSE.
        lv_borrow = 0.
      ENDIF.
      APPEND lv_value TO rt_result.
    ENDDO.
  ENDMETHOD.


  METHOD to_limbs.
* big-endian xstring -> little-endian base-2^15 limbs, natural length
    DATA lv_x      TYPE xstring.
    DATA lv_len    TYPE i.
    DATA lv_off    TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.
    DATA lv_acc    TYPE i.
    DATA lv_bits   TYPE i.
    DATA lv_factor TYPE i.

    lv_x = normalize( iv_x ).
    lv_len = xstrlen( lv_x ).
    DO lv_len TIMES.
      lv_off = lv_len - sy-index.
      lv_byte = lv_x+lv_off(1).
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
      lv_acc = lv_acc + lv_byte * lv_factor.
      lv_bits = lv_bits + 8.
      WHILE lv_bits >= 15.
        APPEND lv_acc MOD c_base TO rt_limbs.
        lv_acc = lv_acc DIV c_base.
        lv_bits = lv_bits - 15.
      ENDWHILE.
    ENDDO.
    WHILE lv_acc > 0.
      APPEND lv_acc MOD c_base TO rt_limbs.
      lv_acc = lv_acc DIV c_base.
    ENDWHILE.
    IF rt_limbs IS INITIAL.
      APPEND 0 TO rt_limbs.
    ENDIF.
  ENDMETHOD.


  METHOD from_limbs.
* little-endian base-2^15 limbs -> normalized big-endian xstring
    DATA lv_acc    TYPE i.
    DATA lv_bits   TYPE i.
    DATA lv_factor TYPE i.
    DATA lv_byte   TYPE x LENGTH 1.
    DATA lv_limb   TYPE i.
    DATA lv_le     TYPE xstring.
    DATA lv_off    TYPE i.

    LOOP AT it_limbs INTO lv_limb.
      lv_factor = 1.
      DO lv_bits TIMES.
        lv_factor = lv_factor * 2.
      ENDDO.
      lv_acc = lv_acc + lv_limb * lv_factor.
      lv_bits = lv_bits + 15.
      WHILE lv_bits >= 8.
        lv_byte = lv_acc MOD 256.
        CONCATENATE lv_le lv_byte INTO lv_le IN BYTE MODE.
        lv_acc = lv_acc DIV 256.
        lv_bits = lv_bits - 8.
      ENDWHILE.
    ENDLOOP.
    WHILE lv_acc > 0.
      lv_byte = lv_acc MOD 256.
      CONCATENATE lv_le lv_byte INTO lv_le IN BYTE MODE.
      lv_acc = lv_acc DIV 256.
    ENDWHILE.

* reverse the little-endian bytes to big-endian
    lv_off = xstrlen( lv_le ).
    WHILE lv_off > 0.
      lv_off = lv_off - 1.
      lv_byte = lv_le+lv_off(1).
      CONCATENATE rv_r lv_byte INTO rv_r IN BYTE MODE.
    ENDWHILE.
    rv_r = normalize( rv_r ).
  ENDMETHOD.
ENDCLASS.
