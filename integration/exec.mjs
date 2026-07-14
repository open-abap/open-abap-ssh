await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const command = process.env.OASSH_COMMAND ?? "printf open-abap-ssh";
const expected = process.env.OASSH_EXPECTED ?? "open-abap-ssh";
const privateSeed = process.env.OASSH_PRIVATE_SEED;
const debug = process.env.OASSH_DEBUG === "1";

const session = await createClient({host, port, user, password, privateSeed, debug});
const {client} = session;
await connectClient(session);

// The ABAP-side operation timeout (default 300s) bounds the pump; pure-ABAP
// RSA host-key verification of a 3072-bit key is slow when transpiled, so
// the generous default is required head-room, not an accident.
const output = (await client.execute({iv_command: new abap.types.String().set(command)})).get();
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
const cipherAlgorithm = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().get_cipher_algorithm()).get();
const hostKeyAlgorithm = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().get_host_key_algorithm()).get();
if (process.env.OASSH_EXPECT_REKEY === "1" && rekeyCount < 1) {
  throw new Error("Expected the server to initiate rekeying");
}
if (process.env.OASSH_EXPECT_STRICT_KEX === "1" && !strictKex) {
  throw new Error("Expected strict KEX negotiation");
}
if (process.env.OASSH_EXPECT_KEX && kexAlgorithm !== process.env.OASSH_EXPECT_KEX) {
  throw new Error(`Expected KEX ${process.env.OASSH_EXPECT_KEX}, got ${kexAlgorithm}`);
}
if (process.env.OASSH_EXPECT_CIPHER && cipherAlgorithm !== process.env.OASSH_EXPECT_CIPHER) {
  throw new Error(`Expected cipher ${process.env.OASSH_EXPECT_CIPHER}, got ${cipherAlgorithm}`);
}
if (process.env.OASSH_EXPECT_HOST_KEY && hostKeyAlgorithm !== process.env.OASSH_EXPECT_HOST_KEY) {
  throw new Error(`Expected host key ${process.env.OASSH_EXPECT_HOST_KEY}, got ${hostKeyAlgorithm}`);
}
console.log(`exec succeeded: ${JSON.stringify(output)}`);
if (rekeyCount > 0) console.log(`server-initiated rekey succeeded (${rekeyCount})`);
if (strictKex) console.log("strict KEX negotiated");
console.log(`KEX algorithm: ${kexAlgorithm}`);
console.log(`cipher algorithm: ${cipherAlgorithm}`);
console.log(`host key algorithm: ${hostKeyAlgorithm}`);
