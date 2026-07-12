// Loads the transpiled runtime and every open-abap-ssh class in
// dependency order. Shared by the integration drivers; keep the order
// intact when adding classes.
await import("../output/init.mjs");
for (const module of [
  "zcl_oassh_ascii.clas.mjs",
  "zcx_oassh_error.clas.mjs",
  "zcl_oassh_stream.clas.mjs",
  "zcl_oassh_sha256.clas.mjs",
  "zcl_oassh_hmac.clas.mjs",
  "zcl_oassh_bigint.clas.mjs",
  "zcl_oassh_x25519.clas.mjs",
  "zcl_oassh_group14.clas.mjs",
  "zcl_oassh_kdf.clas.mjs",
  "zcl_oassh_rsa.clas.mjs",
  "zcl_oassh_sha512.clas.mjs",
  "zcl_oassh_ed25519.clas.mjs",
  "zcl_oassh_aes.clas.mjs",
  "zcl_oassh_ctr.clas.mjs",
  "zcl_oassh_chacha20.clas.mjs",
  "zcl_oassh_poly1305.clas.mjs",
  "zcl_oassh_chachapoly.clas.mjs",
  "zcl_oassh_packet.clas.mjs",
  "zcl_oassh_message_20.clas.mjs",
  "zcl_oassh_message_21.clas.mjs",
  "zcl_oassh_message_ecdh_30.clas.mjs",
  "zcl_oassh_message_ecdh_31.clas.mjs",
  "zcl_oassh_message_dh_30.clas.mjs",
  "zcl_oassh_message_dh_31.clas.mjs",
  "zcl_oassh_message_5.clas.mjs",
  "zcl_oassh_message_6.clas.mjs",
  "zcl_oassh_message_50.clas.mjs",
  "zcl_oassh_message_51.clas.mjs",
  "zcl_oassh_message_52.clas.mjs",
  "zcl_oassh_message_53.clas.mjs",
  "zcl_oassh_channel.clas.mjs",
  "zcl_oassh_transport.clas.mjs",
  "zcl_oassh.clas.mjs",
]) {
  await import(`../output/${module}`);
}
