import net from "node:net";
import crypto from "node:crypto";

await import("./load-modules.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const input = Buffer.from(process.env.OASSH_SHELL_INPUT_HEX
  ?? "7072696E7466206F70656E2D616261702D7373682D7368656C6C0A657869740A", "hex");
const expected = Buffer.from(process.env.OASSH_SHELL_EXPECTED ?? "open-abap-ssh-shell");

let handler;
let socket;
let callbackQueue = Promise.resolve();
let rejectSocket;
let shellComplete = false;
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
      callbackQueue = callbackQueue
        .then(() => handler.get().zif_oassh_socket_handler$on_message({
          iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
        }))
        .catch(rejectSocket);
    });
    socket.once("error", rejectSocket);
    socket.once("close", hadError => {
      if (hadError || !shellComplete) {
        rejectSocket(new Error("OpenSSH socket closed before SSH shell completed"));
      }
    });
  },
  async zif_oassh_socket$send({iv_data}) {
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

const shellRun = client.shell({
  iv_input: new abap.types.XString().set(input.toString("hex").toUpperCase()),
}).then(value => {
  shellComplete = true;
  return value;
});
let timer;
const timeout = new Promise((_, reject) => {
  timer = setTimeout(() => reject(new Error("Timed out waiting for SSH shell")), 300000);
});
let outputValue;
try {
  outputValue = await Promise.race([shellRun, socketFailure, timeout]);
} finally {
  clearTimeout(timer);
}
const output = Buffer.from(outputValue.get(), "hex");
const exitStatus = (await client.get_exit_status()).get();
await client.close();

if (!output.includes(expected)) {
  throw new Error(`Expected terminal marker ${JSON.stringify(expected.toString())}, got ${JSON.stringify(output.toString())}`);
}
if (exitStatus !== 0) {
  throw new Error(`Expected shell exit status 0, got ${exitStatus}`);
}
console.log(`shell succeeded: ${JSON.stringify(expected.toString())}`);
