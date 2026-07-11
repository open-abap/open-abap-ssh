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
  "zcl_oassh_aes.clas.mjs",
  "zcl_oassh_ctr.clas.mjs",
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

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const command = process.env.OASSH_COMMAND ?? "printf open-abap-ssh";
const expected = process.env.OASSH_EXPECTED ?? "open-abap-ssh";

let handler;
let socket;
let callbackQueue = Promise.resolve();
let rejectSocket;
const debug = process.env.OASSH_DEBUG === "1";
const socketFailure = new Promise((_, reject) => { rejectSocket = reject; });

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
const socketAdapter = {
  async zif_oassh_socket$set_handler({ii_handler}) {
    handler = ii_handler;
  },
  async zif_oassh_socket$connect() {
    socket = net.createConnection({host, port});
    socket.once("connect", () => {
      if (debug) console.error("socket connected");
      callbackQueue = callbackQueue.then(
        () => handler.get().zif_oassh_socket_handler$on_open(),
      );
    });
    socket.on("data", data => {
      if (debug) console.error(`received ${data.length} bytes`);
      callbackQueue = callbackQueue
        .then(() => handler.get().zif_oassh_socket_handler$on_message({
          iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
        }))
        .then(() => {
          const core = client.FRIENDS_ACCESS_INSTANCE;
          const transport = core.mo_transport.get();
          const auth = transport?.FRIENDS_ACCESS_INSTANCE.mv_auth_state.get();
          const transportState = transport?.FRIENDS_ACCESS_INSTANCE.mv_state.get();
          if (!debug) return;
          const channel = core.mo_channel.get();
          const channelState = channel?.FRIENDS_ACCESS_INSTANCE.mv_state.get();
          console.error(`processed transport=${transportState} auth=${auth} channel=${channelState}`);
        })
        .catch(rejectSocket);
    });
    socket.once("error", rejectSocket);
    socket.once("close", hadError => {
      if (hadError) rejectSocket(new Error("OpenSSH socket closed with an error"));
    });
  },
  async zif_oassh_socket$send({iv_data}) {
    if (debug) console.error(`sending ${iv_data.get().length / 2} bytes`);
    socket.write(Buffer.from(iv_data.get(), "hex"));
  },
  async zif_oassh_socket$close() {
    socket.end();
  },
  async zif_oassh_socket$wait({iv_timeout_seconds}) {
    const deadline = Date.now() + iv_timeout_seconds.get() * 1000;
    while ((await handler.get().zif_oassh_socket_handler$is_complete()).get() !== "X") {
      if (Date.now() >= deadline) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
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

const execution = client.execute({iv_command: new abap.types.String().set(command)});
let timer;
const timeout = new Promise((_, reject) => {
  timer = setTimeout(() => reject(new Error("Timed out waiting for SSH exec")), 300000);
});
let outputValue;
try {
  outputValue = await Promise.race([execution, socketFailure, timeout]);
} finally {
  clearTimeout(timer);
}
const output = outputValue.get();
const exitStatus = (await client.get_exit_status()).get();
await client.close();

if (output !== expected) {
  throw new Error(`Expected stdout ${JSON.stringify(expected)}, got ${JSON.stringify(output)}`);
}
if (exitStatus !== 0) {
  throw new Error(`Expected exit status 0, got ${exitStatus}`);
}
const rekeyCount = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().get_rekey_count()).get();
const strictKex = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().is_strict_kex()).get() === "X";
const kexAlgorithm = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().get_kex_algorithm()).get();
if (process.env.OASSH_EXPECT_REKEY === "1" && rekeyCount < 1) {
  throw new Error("Expected the server to initiate rekeying");
}
if (process.env.OASSH_EXPECT_STRICT_KEX === "1" && !strictKex) {
  throw new Error("Expected strict KEX negotiation");
}
if (process.env.OASSH_EXPECT_KEX && kexAlgorithm !== process.env.OASSH_EXPECT_KEX) {
  throw new Error(`Expected KEX ${process.env.OASSH_EXPECT_KEX}, got ${kexAlgorithm}`);
}
console.log(`exec succeeded: ${JSON.stringify(output)}`);
if (rekeyCount > 0) console.log(`server-initiated rekey succeeded (${rekeyCount})`);
if (strictKex) console.log("strict KEX negotiated");
console.log(`KEX algorithm: ${kexAlgorithm}`);
