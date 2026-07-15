await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const listPath = process.env.OASSH_SFTP_LIST_PATH ?? "/config/oassh-list";
const filePath = process.env.OASSH_SFTP_FILE_PATH ?? "/config/oassh-list/a.bin";
const fileExpected = process.env.OASSH_SFTP_FILE_EXPECTED ?? "a";
// Large fixtures are checked by byte length instead of an unwieldy content
// literal; a set value also lets the scenario cross a small RekeyLimit.
const fileBytes = process.env.OASSH_SFTP_FILE_BYTES ? Number(process.env.OASSH_SFTP_FILE_BYTES) : undefined;
const requireRekey = process.env.OASSH_SFTP_REQUIRE_REKEY === "1";
const renameBase = process.env.OASSH_SFTP_RENAME_PATH ?? "/config/oassh-session";
const debug = process.env.OASSH_DEBUG === "1";

const text = value => new abap.types.String().set(value);

// One connection, one host-key verification, one sftp subsystem channel: every
// operation below runs inside a single session opened with sftp_open( ).
const session = await createClient({host, port, user, password, debug});
const {client} = session;
await connectClient(session);

await client.sftp_open({});

// LIST
const names = await client.sftp_list({iv_path: text(listPath)});
const listed = names.array()
  .map(row => Buffer.from(row.get().filename.get(), "hex").toString("utf8"))
  .filter(name => name !== "." && name !== "..")
  .sort();
if (listed.length === 0) {
  throw new Error(`Expected a non-empty listing for ${listPath}`);
}

// DOWNLOAD
const data = await client.sftp_download({iv_path: text(filePath)});
const downloadedBuffer = Buffer.from(data.get(), "hex");
if (fileBytes !== undefined) {
  if (downloadedBuffer.length !== fileBytes) {
    throw new Error(`Expected download of ${fileBytes} bytes, got ${downloadedBuffer.length}`);
  }
} else if (downloadedBuffer.toString("utf8") !== fileExpected) {
  throw new Error(`Expected download ${fileExpected}, got ${downloadedBuffer.toString("utf8")}`);
}
const downloaded = fileBytes !== undefined ? `${downloadedBuffer.length} bytes` : downloadedBuffer.toString("utf8");

// STAT
const attrs = await client.sftp_stat({iv_path: text(filePath)});
if (attrs.get().has_size.get() !== "X") {
  throw new Error(`Expected STAT of ${filePath} to report a size`);
}

// RENAME (source.bin -> renamed.bin) then restore the fixture for reruns
await client.sftp_rename({
  iv_old_path: text(`${renameBase}/source.bin`),
  iv_new_path: text(`${renameBase}/renamed.bin`),
});
await client.sftp_rename({
  iv_old_path: text(`${renameBase}/renamed.bin`),
  iv_new_path: text(`${renameBase}/source.bin`),
});

// The session is still healthy: mo_sftp is back to ready (2), not finished,
// and the channel is still running (4) between operations.
const sftp = client.FRIENDS_ACCESS_INSTANCE.mo_sftp.get();
const channel = client.FRIENDS_ACCESS_INSTANCE.mo_channel.get();
if (sftp.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 2) {
  throw new Error("SFTP session did not return to ready between operations");
}
if (channel.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 4) {
  throw new Error("SFTP session channel closed prematurely");
}

const rekeyCount = (await client.FRIENDS_ACCESS_INSTANCE.mo_transport.get().get_rekey_count()).get();
if (requireRekey && Number(rekeyCount) < 1) {
  throw new Error("Expected at least one rekey during the session");
}

await client.sftp_close({});
if (channel.FRIENDS_ACCESS_INSTANCE.mv_state.get() !== 7) {
  throw new Error("SFTP session channel did not complete the close handshake");
}
await client.close();

console.log(
  `sftp session succeeded: list=${listed.join(",")} download=${downloaded} ` +
  `stat+rename over one connection (rekeys: ${rekeyCount})`);
