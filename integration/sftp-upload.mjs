import net from "node:net";
import crypto from "node:crypto";

await import("./load-modules.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_UPLOAD_PATH ?? "/config/sftp-upload.bin";
const debug = process.env.OASSH_DEBUG === "1";
const payload = Buffer.concat([Buffer.alloc(32768, 0x5A), Buffer.from([0x00, 0xFF])]);

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

async function createClient(label) {
  let handler;
  let socket;
  let callbackQueue = Promise.resolve();
  let rejectSocket;
  let operationComplete = false;
  const socketFailure = new Promise((_, reject) => { rejectSocket = reject; });
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
        if (debug) console.error(`${label}: received ${data.length} bytes`);
        callbackQueue = callbackQueue
          .then(() => handler.get().zif_oassh_socket_handler$on_message({
            iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
          }))
          .catch(rejectSocket);
      });
      socket.once("error", rejectSocket);
      socket.once("close", hadError => {
        if (hadError || !operationComplete) {
          rejectSocket(new Error(`OpenSSH socket closed before SFTP ${label} completed`));
        }
      });
    },
    async zif_oassh_socket$send({iv_data}) {
      if (debug) console.error(`${label}: sending ${iv_data.get().length / 2} bytes`);
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
  return {
    client,
    socketFailure,
    markComplete() { operationComplete = true; },
  };
}

async function finishOperation(session, operation, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Timed out waiting for SFTP ${label}`)), 300000);
  });
  try {
    return await Promise.race([operation, session.socketFailure, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

const upload = await createClient("upload");
await finishOperation(upload, upload.client.sftp_upload({
  iv_path: new abap.types.String().set(path),
  iv_data: new abap.types.XString().set(payload.toString("hex").toUpperCase()),
}).then(value => {
  upload.markComplete();
  return value;
}), "upload");
await upload.client.close();

const download = await createClient("verification download");
const downloaded = await finishOperation(download, download.client.sftp_download({
  iv_path: new abap.types.String().set(path),
}).then(value => {
  download.markComplete();
  return value;
}), "verification download");
await download.client.close();

const actual = Buffer.from(downloaded.get(), "hex");
if (!actual.equals(payload)) {
  throw new Error(`Uploaded ${payload.length} bytes but downloaded ${actual.length} different bytes`);
}
console.log(`sftp upload succeeded and verified through a second connection: ${payload.length} bytes`);
