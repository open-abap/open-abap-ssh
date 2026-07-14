await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_LIST_PATH ?? "/config/oassh-list";
const expected = (process.env.OASSH_SFTP_LIST_EXPECTED ?? "a.bin,b.txt").split(",").sort();
const debug = process.env.OASSH_DEBUG === "1";

const session = await createClient({host, port, user, password, debug});
const {client} = session;
await connectClient(session);

const names = await client.sftp_list({iv_path: new abap.types.String().set(path)});
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
