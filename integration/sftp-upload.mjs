await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const path = process.env.OASSH_SFTP_UPLOAD_PATH ?? "/config/sftp-upload.bin";
const debug = process.env.OASSH_DEBUG === "1";
const payload = Buffer.concat([Buffer.alloc(32768, 0x5A), Buffer.from([0x00, 0xFF])]);

// A one-shot ZCL_OASSH owns a single session channel, so the verification
// download runs through a second connection.
const upload = await createClient({host, port, user, password, debug});
await connectClient(upload);
await upload.client.sftp_upload({
  iv_path: new abap.types.String().set(path),
  iv_data: new abap.types.XString().set(payload.toString("hex").toUpperCase()),
});
await upload.client.close();

const download = await createClient({host, port, user, password, debug});
await connectClient(download);
const downloaded = await download.client.sftp_download({
  iv_path: new abap.types.String().set(path),
});
await download.client.close();

const actual = Buffer.from(downloaded.get(), "hex");
if (!actual.equals(payload)) {
  throw new Error(`Uploaded ${payload.length} bytes but downloaded ${actual.length} different bytes`);
}
console.log(`sftp upload succeeded and verified through a second connection: ${payload.length} bytes`);
