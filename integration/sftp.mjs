await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_PATH ?? "/config/sftp-fixture.bin";
const expected = (process.env.OASSH_SFTP_EXPECTED_HEX ?? "6F70656E2D616261702D7366747000FF").toUpperCase();
const debug = process.env.OASSH_DEBUG === "1";

const session = await createClient({host, port, user, password, debug});
const {client} = session;
await connectClient(session);

const outputValue = await client.sftp_download({
  iv_path: new abap.types.String().set(path),
});
const output = outputValue.get().toUpperCase();
await client.close();

if (output !== expected) {
  throw new Error(`Expected SFTP bytes ${expected}, got ${output}`);
}
const channel = client.FRIENDS_ACCESS_INSTANCE.mo_channel.get();
const sftp = client.FRIENDS_ACCESS_INSTANCE.mo_sftp.get();
if (channel.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not complete the SSH channel close handshake");
}
if (sftp.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not reach its finished state");
}
console.log(`sftp download succeeded: ${output.length / 2} bytes from ${path}`);
