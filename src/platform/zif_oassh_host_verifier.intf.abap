INTERFACE zif_oassh_host_verifier
  PUBLIC.

* The application owns known-hosts policy. The callback receives the complete
* SSH host-key blob, suitable for exact pinning or fingerprint calculation.
  METHODS verify
    IMPORTING
      iv_host_key       TYPE xstring
    RETURNING
      VALUE(rv_trusted) TYPE abap_bool.
ENDINTERFACE.
