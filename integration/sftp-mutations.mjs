import net from "node:net";
import crypto from "node:crypto";

await import("./load-modules.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const base = process.env.OASSH_SFTP_MUTATION_PATH ?? "/config/oassh-mutations";

async function runOperation(label, invoke) {
  let handler;
  let socket;
  let operationComplete = false;
  let rejectSocket;
  let callbackQueue = Promise.resolve();
  const socketFailure = new Promise((_, reject) => { rejectSocket = reject; });
  const random = {
    async zif_oassh_random$bytes({iv_length}) {
      const value = crypto.randomBytes(iv_length.get());
      return new abap.types.XString().set(value.toString("hex").toUpperCase());
    },
  };
  const hostVerifier = {
    async zif_oassh_host_verifier$verify() { return abap.builtin.abap_true; },
  };
  const adapter = {
    async zif_oassh_socket$set_handler({ii_handler}) { handler = ii_handler; },
    async zif_oassh_socket$connect() {
      socket = net.createConnection({host, port});
      socket.once("connect", () => {
        callbackQueue = callbackQueue.then(
          () => handler.get().zif_oassh_socket_handler$on_open(),
        );
      });
      socket.on("data", data => {
        callbackQueue = callbackQueue
          .then(() => handler.get().zif_oassh_socket_handler$on_message({
            iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
          }))
          .catch(rejectSocket);
      });
      socket.once("error", rejectSocket);
      socket.once("close", hadError => {
        if (hadError || !operationComplete) {
          rejectSocket(new Error(`OpenSSH socket closed before ${label} completed`));
        }
      });
    },
    async zif_oassh_socket$send({iv_data}) {
      socket.write(Buffer.from(iv_data.get(), "hex"));
    },
    async zif_oassh_socket$close() { socket.end(); },
    async zif_oassh_socket$wait({iv_timeout_seconds}) {
      const deadline = Date.now() + iv_timeout_seconds.get() * 1000;
      while ((await handler.get().zif_oassh_socket_handler$is_complete()).get() !== "X") {
        if (Date.now() >= deadline) return;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    },
  };
  const socketRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET"}).set(adapter);
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
  await adapter.zif_oassh_socket$set_handler({ii_handler: clientRef});
  await adapter.zif_oassh_socket$connect();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 300000);
  });
  try {
    await Promise.race([invoke(client), socketFailure, timeout]);
    operationComplete = true;
  } finally {
    clearTimeout(timer);
    await client.close();
  }
}

const text = value => new abap.types.String().set(value);
await runOperation("SFTP MKDIR", client => client.sftp_mkdir({iv_path: text(`${base}/newdir`)}));
await runOperation("SFTP RENAME", client => client.sftp_rename({
  iv_old_path: text(`${base}/source.bin`),
  iv_new_path: text(`${base}/renamed.bin`),
}));
await runOperation("SFTP REMOVE", client => client.sftp_remove({iv_path: text(`${base}/renamed.bin`)}));
await runOperation("SFTP RMDIR", client => client.sftp_rmdir({iv_path: text(`${base}/newdir`)}));
console.log(`sftp mutations succeeded below ${base}`);
