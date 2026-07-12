import net from "node:net";
import crypto from "node:crypto";

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
  "zcl_oassh_transport.clas.mjs",
  "zcl_oassh.clas.mjs",
]) {
  await import(`../output/${module}`);
}

const host = process.argv[2] ?? process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.argv[3] ?? process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const debug = process.env.OASSH_DEBUG === "1" || process.argv.includes("--debug");

// SSH_MSG_USERAUTH_SUCCESS moves the transport auth state machine to this value.
const AUTH_STATE_AUTHENTICATED = 3;

let handler;
let socket;
let callbackQueue = Promise.resolve();
let done = false;
let resolveAuth;
let rejectAuth;
const authenticated = new Promise((resolve, reject) => {
  resolveAuth = resolve;
  rejectAuth = reject;
});

const random = {
  async zif_oassh_random$bytes({iv_length}) {
    const value = crypto.randomBytes(iv_length.get());
    return new abap.types.XString().set(value.toString("hex").toUpperCase());
  },
};
const hostVerifier = {
  async zif_oassh_host_verifier$verify() {
    return abap.builtin.abap_true;
  },
};

const authState = () => {
  const client = handler.get().FRIENDS_ACCESS_INSTANCE;
  const transport = client.mo_transport.get();
  if (!transport) return 0;
  return transport.FRIENDS_ACCESS_INSTANCE.mv_auth_state.get();
};

const socketAdapter = {
  async zif_oassh_socket$set_handler({ii_handler}) {
    handler = ii_handler;
  },
  async zif_oassh_socket$connect() {
    socket = net.createConnection({host, port});
    socket.once("connect", () => {
      if (debug) console.error("connected");
      callbackQueue = callbackQueue.then(() => handler.get().zif_oassh_socket_handler$on_open());
    });
    socket.on("data", data => {
      if (done) return;
      if (debug) console.error(`received ${data.length} bytes`);
      callbackQueue = callbackQueue
        .then(() => done || handler.get().zif_oassh_socket_handler$on_message({
          iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
        }))
        .then(() => {
          if (debug) console.error(`auth state ${authState()}`);
          if (authState() === AUTH_STATE_AUTHENTICATED) { done = true; resolveAuth(); }
        })
        .catch(error => { if (!done) rejectAuth(error); });
    });
    socket.once("error", rejectAuth);
    socket.once("close", () => rejectAuth(new Error("OpenSSH closed before authentication")));
  },
  async zif_oassh_socket$send({iv_data}) {
    const data = Buffer.from(iv_data.get(), "hex");
    if (debug) console.error(`sending ${data.length} bytes`);
    socket.write(data);
  },
  async zif_oassh_socket$close() {
    socket.end();
  },
  async zif_oassh_socket$wait() {
    return;
  },
};

const socketRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET"}).set(socketAdapter);
const randomRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_RANDOM"}).set(random);
const verifierRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_HOST_VERIFIER"}).set(hostVerifier);
const client = await new abap.Classes.ZCL_OASSH().constructor_({
  ii_socket: socketRef,
  ii_random: randomRef,
  ii_host_verifier: verifierRef,
  iv_user: new abap.types.String().set(user),
  iv_password: new abap.types.String().set(password),
});
const clientRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET_HANDLER"}).set(client);
await socketAdapter.zif_oassh_socket$set_handler({ii_handler: clientRef});
await socketAdapter.zif_oassh_socket$connect();

// Pure-ABAP RSA host-key verification of a 3072-bit key is slow when
// transpiled, so allow generous head-room over the handshake crypto.
let timer;
const timeout = new Promise((_, reject) => {
  timer = setTimeout(() => reject(new Error(`Timed out waiting for authentication (auth state ${authState()})`)), 300000);
});
try {
  await Promise.race([authenticated, timeout]);
} finally {
  clearTimeout(timer);
}
socket.end();
console.log(`password authentication succeeded as ${user}`);
