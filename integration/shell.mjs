await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.env.OASSH_PORT ?? "2222");
const user = process.env.OASSH_USER ?? "test";
const password = process.env.OASSH_PASSWORD ?? "test";
const input = Buffer.from(process.env.OASSH_SHELL_INPUT_HEX
  ?? "7072696E7466206F70656E2D616261702D7373682D7368656C6C0A657869740A", "hex");
const expected = Buffer.from(process.env.OASSH_SHELL_EXPECTED ?? "open-abap-ssh-shell");
const debug = process.env.OASSH_DEBUG === "1";

const session = await createClient({host, port, user, password, debug});
const {client} = session;
await connectClient(session);

const outputValue = await client.shell({
  iv_input: new abap.types.XString().set(input.toString("hex").toUpperCase()),
});
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
