await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const base = process.env.OASSH_SFTP_MUTATION_PATH ?? "/config/oassh-mutations";
const debug = process.env.OASSH_DEBUG === "1";

// A one-shot ZCL_OASSH owns a single session channel, so every mutation runs
// through its own connection.
async function runOperation(label, invoke) {
  const session = await createClient({host, port, user, password, debug});
  await connectClient(session);
  try {
    return await invoke(session.client);
  } finally {
    await session.client.close();
  }
}

const text = value => new abap.types.String().set(value);
const canonical = await runOperation("SFTP REALPATH", client => client.sftp_realpath({
  iv_path: text(base),
}));
const canonicalPath = Buffer.from(canonical.get().filename.get(), "hex").toString("utf8");
if (canonicalPath !== base) {
  throw new Error(`Expected canonical path ${base}, got ${canonicalPath}`);
}
await runOperation("SFTP MKDIR", client => client.sftp_mkdir({iv_path: text(`${base}/newdir`)}));
await runOperation("SFTP RENAME", client => client.sftp_rename({
  iv_old_path: text(`${base}/source.bin`),
  iv_new_path: text(`${base}/renamed.bin`),
}));
await runOperation("SFTP REMOVE", client => client.sftp_remove({iv_path: text(`${base}/renamed.bin`)}));
await runOperation("SFTP RMDIR", client => client.sftp_rmdir({iv_path: text(`${base}/newdir`)}));
console.log(`sftp REALPATH and mutations succeeded below ${base}`);
