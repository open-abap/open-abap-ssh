INTERFACE zif_oassh_host_verifier
  PUBLIC.

* The application owns known-hosts policy. Bind trust to the exact connection
* endpoint as well as the complete host-key blob; this supports OpenSSH-style
* host/port-specific pinning instead of accidentally trusting a key globally.
  METHODS verify
    IMPORTING
      iv_host           TYPE string
      iv_port           TYPE string
      iv_host_key       TYPE xstring
    RETURNING
      VALUE(rv_trusted) TYPE abap_bool ##NEEDED.
ENDINTERFACE.
