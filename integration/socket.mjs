// Shared plumbing for the integration drivers: a zif_oassh_socket adapter
// over a Node TCP socket plus a ZCL_OASSH client factory. The SSH core pulls
// inbound bytes with read( ); the data events here only buffer chunks.
// Requires ./load-modules.mjs to have been imported first (abap global).
import net from "node:net";
import crypto from "node:crypto";

export function createSocketAdapter({host, port, debug = false, onData, onSend} = {}) {
  let socket;
  let closed = false;
  const chunks = [];
  let notify;

  const wake = () => {
    if (notify) {
      const resolve = notify;
      notify = undefined;
      resolve();
    }
  };

  return {
    async zif_oassh_socket$connect() {
      socket = net.createConnection({host, port});
      socket.once("connect", () => {
        if (debug) console.error("socket connected");
      });
      socket.on("data", data => {
        if (debug) console.error(`received ${data.length} bytes`);
        chunks.push(data);
        onData?.(data);
        wake();
      });
      socket.once("error", error => {
        if (debug) console.error(`socket error: ${error.message}`);
        closed = true;
        wake();
      });
      socket.once("close", () => {
        if (debug) console.error("socket closed");
        closed = true;
        wake();
      });
    },
    async zif_oassh_socket$send({iv_data}) {
      const data = Buffer.from(iv_data.get(), "hex");
      if (debug) console.error(`sending ${data.length} bytes`);
      onSend?.(data);
      socket.write(data);
    },
    async zif_oassh_socket$read({iv_timeout_seconds}) {
      if (chunks.length === 0 && !closed) {
        await new Promise(resolve => {
          const timer = setTimeout(() => {
            notify = undefined;
            resolve();
          }, iv_timeout_seconds.get() * 1000);
          notify = () => {
            clearTimeout(timer);
            resolve();
          };
        });
      }
      const data = Buffer.concat(chunks.splice(0, chunks.length));
      return new abap.types.XString().set(data.toString("hex").toUpperCase());
    },
    async zif_oassh_socket$is_closed() {
      return closed ? abap.builtin.abap_true : abap.builtin.abap_false;
    },
    async zif_oassh_socket$close() {
      socket?.end();
    },
  };
}

export function createSecureRandom() {
  return {
    async zif_oassh_random$bytes({iv_length}) {
      const value = crypto.randomBytes(iv_length.get());
      return new abap.types.XString().set(value.toString("hex").toUpperCase());
    },
  };
}

// Builds a ZCL_OASSH client wired to a fresh socket adapter with Node secure
// randomness and an accept-all host verifier (local tests only). Returns the
// client and adapter without connecting.
export async function createClient({user, password, privateSeed, random, ...adapterOptions}) {
  const adapter = createSocketAdapter(adapterOptions);
  const hostVerifier = {
    async zif_oassh_host_verifier$verify() {
      return abap.builtin.abap_true;
    },
  };
  const client = await new abap.Classes.ZCL_OASSH().constructor_({
    ii_socket: new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET"}).set(adapter),
    ii_random: new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_RANDOM"}).set(random ?? createSecureRandom()),
    ii_host_verifier: new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_HOST_VERIFIER"}).set(hostVerifier),
    iv_user: new abap.types.String().set(user),
    iv_password: new abap.types.String().set(password),
    iv_private_seed: new abap.types.XString().set(privateSeed ?? ""),
  });
  return {client, adapter};
}

// Mirrors zcl_oassh=>connect: open the TCP connection and send the client
// version line. Operations called afterwards pump the protocol themselves.
export async function connectClient({client, adapter}) {
  await adapter.zif_oassh_socket$connect();
  await client.FRIENDS_ACCESS_INSTANCE.send_version();
}
