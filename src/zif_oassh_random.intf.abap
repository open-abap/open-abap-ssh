INTERFACE zif_oassh_random
  PUBLIC.

* source of random bytes, e.g. for the SSH_MSG_KEXINIT cookie and
* ephemeral key material. Kept behind an interface so tests can inject a
* deterministic, fixed generator.
  METHODS bytes
    IMPORTING
      iv_length     TYPE i
    RETURNING
      VALUE(rv_hex) TYPE xstring.
ENDINTERFACE.
