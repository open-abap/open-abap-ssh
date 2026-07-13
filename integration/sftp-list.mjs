import net from "node:net";
import crypto from "node:crypto";

await import("./load-modules.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_LIST_PATH ?? "/config/oassh-list";
const expected = (process.env.OASSH_SFTP_LIST_EXPECTED ?? "a.bin,b.txt").split(",").sort();
const debug = process.env.OASSH_DEBUG === "1";

let handler;
let socket;
let callbackQueue = Promise.resolve();
let rejectSocket;
let operationComplete = false;
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
        .catch(rejectSocket);
    });
    socket.once("error", rejectSocket);
    socket.once("close", hadError => {
      if (hadError || !operationComplete) {
        rejectSocket(new Error("OpenSSH socket closed before SFTP directory listing completed"));
      }
    });
  },
  async zif_oassh_socket$send({iv_data}) {
    if (debug) console.error(`sending ${iv_data.get().length / 2} bytes`);
    const data = Buffer.from(iv_data.get(), "hex");
    socket.write(data);
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

const list = client.sftp_list({iv_path: new abap.types.String().set(path)}).then(value => {
  operationComplete = true;
  return value;
});
let timer;
const timeout = new Promise((_, reject) => {
  timer = setTimeout(() => reject(new Error("Timed out waiting for SFTP directory listing")), 300000);
});
let names;
try {
  names = await Promise.race([list, socketFailure, timeout]);
} finally {
  clearTimeout(timer);
}
await client.close();

const actual = names.array()
  .map(row => Buffer.from(row.get().filename.get(), "hex").toString("utf8"))
  .filter(name => name !== "." && name !== "..")
  .sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  throw new Error(`Expected SFTP names ${expected.join(",")}, got ${actual.join(",")}`);
}
const channel = client.FRIENDS_ACCESS_INSTANCE.mo_channel.get();
const sftp = client.FRIENDS_ACCESS_INSTANCE.mo_sftp.get();
if (channel.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not complete the SSH channel close handshake");
}
if (sftp.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not reach its finished state");
}
console.log(`sftp directory listing succeeded: ${actual.join(",")} from ${path}`);
