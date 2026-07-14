await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.argv[2] ?? process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.argv[3] ?? process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const privateSeed = process.env.OASSH_PRIVATE_SEED;
const debug = process.env.OASSH_DEBUG === "1" || process.argv.includes("--debug");

// SSH_MSG_USERAUTH_SUCCESS moves the transport auth state machine to this value.
const AUTH_STATE_AUTHENTICATED = 3;

const session = await createClient({host, port, user, password, privateSeed, debug});
const {client, adapter} = session;
const core = client.FRIENDS_ACCESS_INSTANCE;

const authState = () => {
  const transport = core.mo_transport.get();
  if (!transport) return 0;
  return transport.FRIENDS_ACCESS_INSTANCE.mv_auth_state.get();
};

await connectClient(session);

// No public operation runs here, so pump the protocol manually until the
// transport authenticates. Pure-ABAP RSA host-key verification of a 3072-bit
// key is slow when transpiled, so allow generous head-room over the
// handshake crypto.
const deadline = Date.now() + 300000;
while (authState() !== AUTH_STATE_AUTHENTICATED) {
  if (Date.now() >= deadline) {
    throw new Error(`Timed out waiting for authentication (auth state ${authState()})`);
  }
  const data = await adapter.zif_oassh_socket$read({
    iv_timeout_seconds: new abap.types.Integer().set(30),
  });
  if (data.get() === "") {
    if ((await adapter.zif_oassh_socket$is_closed()).get() === "X") {
      throw new Error("OpenSSH closed before authentication");
    }
    continue;
  }
  await core.process_inbound({iv_data: data});
  if (debug) console.error(`auth state ${authState()}`);
}
await adapter.zif_oassh_socket$close();
console.log(`password authentication succeeded as ${user}`);
