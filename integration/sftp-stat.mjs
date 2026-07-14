await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_STAT_PATH ?? "/config/sftp-fixture.bin";
const expectedSize = (process.env.OASSH_SFTP_STAT_SIZE_HEX ?? "0000000000000010").toUpperCase();
const useLstat = process.env.OASSH_SFTP_LSTAT === "1";
const debug = process.env.OASSH_DEBUG === "1";

const session = await createClient({host, port, user, password, debug});
const {client} = session;
await connectClient(session);

const statMethod = useLstat ? client.sftp_lstat.bind(client) : client.sftp_stat.bind(client);
const attrs = await statMethod({iv_path: new abap.types.String().set(path)});
await client.close();

const attrsValue = attrs.get();
const size = attrsValue.size.get().toUpperCase();
if (attrsValue.has_size.get() !== "X" || size !== expectedSize) {
  throw new Error(`Expected SFTP size ${expectedSize}, got ${size}`);
}
const channel = client.FRIENDS_ACCESS_INSTANCE.mo_channel.get();
const sftp = client.FRIENDS_ACCESS_INSTANCE.mo_sftp.get();
if (channel.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not complete the SSH channel close handshake");
}
if (sftp.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP operation did not reach its finished state");
}
console.log(`sftp ${useLstat ? "LSTAT" : "STAT"} succeeded: size ${size} for ${path}`);
