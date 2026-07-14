import crypto from "node:crypto";

await import("./load-modules.mjs");
const {createClient, connectClient} = await import("./socket.mjs");

const host = process.argv[2] ?? process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.argv[3] ?? process.env.OASSH_PORT ?? "2222");
const debug = process.env.OASSH_DEBUG === "1" || process.argv.includes("--debug");

// SSH transport state machine value once NEWKEYS completed in both directions.
const STATE_ENCRYPTED = 3;

const receivedChunks = [];
const sentChunks = [];
const randomCalls = [];

const random = {
  async zif_oassh_random$bytes({iv_length}) {
    const value = crypto.randomBytes(iv_length.get());
    randomCalls.push(value);
    return new abap.types.XString().set(value.toString("hex").toUpperCase());
  },
};

const session = await createClient({
  host,
  port,
  user: process.env.OASSH_USER ?? "test",
  password: process.env.OASSH_PASSWORD ?? "test",
  debug,
  random,
  onData: data => receivedChunks.push(data),
  onSend: data => sentChunks.push(data),
});
const {client, adapter} = session;
const core = client.FRIENDS_ACCESS_INSTANCE;

function dumpKexDiagnostics() {
  const transport = core.mo_transport.get();
  console.error(`exchange hash ${transport.FRIENDS_ACCESS_INSTANCE.mv_h.get()}`);
  const packet = receivedChunks.at(-1);
  if (!(packet?.length > 10 && packet[5] === 31)) return;
  let offset = 6;
  const takeString = () => {
    const length = packet.readUInt32BE(offset); offset += 4;
    const value = packet.subarray(offset, offset + length); offset += length;
    return value;
  };
  const hostKey = takeString();
  takeString();
  const signatureBlob = takeString();
  const algorithmLength = signatureBlob.readUInt32BE(0);
  console.error(`signature algorithm ${signatureBlob.subarray(4, 4 + algorithmLength)}`);
  let hostOffset = 0;
  const hostString = () => {
    const length = hostKey.readUInt32BE(hostOffset); hostOffset += 4;
    const value = hostKey.subarray(hostOffset, hostOffset + length); hostOffset += length;
    return value;
  };
  hostString();
  const e = hostString();
  let n = hostString();
  if (n[0] === 0) n = n.subarray(1);
  const base64url = value => value.toString("base64url");
  const publicKey = crypto.createPublicKey({
    key: {kty: "RSA", n: base64url(n), e: base64url(e)}, format: "jwk",
  });
  const signatureOffset = 4 + algorithmLength;
  const signatureLength = signatureBlob.readUInt32BE(signatureOffset);
  const rawSignature = signatureBlob.subarray(signatureOffset + 4, signatureOffset + 4 + signatureLength);
  const transportFriends = core.mo_transport.get().FRIENDS_ACCESS_INSTANCE;
  const h = Buffer.from(transportFriends.mv_h.get(), "hex");
  console.error(`node verifies exchange hash: ${crypto.verify("sha256", h, publicKey, rawSignature)}`);
  const packetPayload = packetValue => {
    const padding = packetValue[4];
    return packetValue.subarray(5, packetValue.readUInt32BE(0) + 4 - padding);
  };
  const serverFirst = receivedChunks[0];
  const serverLineEnd = serverFirst.indexOf("\r\n") + 2;
  const serverKex = packetPayload(serverFirst.subarray(serverLineEnd));
  const clientKex = packetPayload(sentChunks[1]);
  const clientEcdh = packetPayload(sentChunks[2]);
  const qC = clientEcdh.subarray(5);
  const serverPublic = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), packet.subarray(6 + 4 + hostKey.length + 4, 6 + 4 + hostKey.length + 4 + 32)]),
    format: "der", type: "spki",
  });
  const scalar = randomCalls.find(value => value.length === 32);
  const clientPrivate = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), scalar]),
    format: "der", type: "pkcs8",
  });
  const shared = crypto.diffieHellman({privateKey: clientPrivate, publicKey: serverPublic});
  const u32 = value => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
  const sshString = value => Buffer.concat([u32(value.length), value]);
  const mpint = value => {
    while (value.length && value[0] === 0) value = value.subarray(1);
    if (value.length && (value[0] & 0x80)) value = Buffer.concat([Buffer.from([0]), value]);
    return sshString(value);
  };
  for (const candidate of [Buffer.from(shared).reverse(), shared]) {
    const candidateH = crypto.createHash("sha256").update(Buffer.concat([
      sshString(sentChunks[0].subarray(0, -2)),
      sshString(serverFirst.subarray(0, serverLineEnd - 2)),
      sshString(clientKex), sshString(serverKex), sshString(hostKey),
      sshString(qC), sshString(packet.subarray(6 + 4 + hostKey.length + 4, 6 + 4 + hostKey.length + 4 + 32)),
      mpint(candidate),
    ])).digest();
    console.error(`candidate ${candidateH.toString("hex")}: ${crypto.verify("sha256", candidateH, publicKey, rawSignature)}`);
  }
}

await connectClient(session);

// No public operation runs here, so pump the protocol manually until the
// transport is encrypted, then stop without authenticating further.
const deadline = Date.now() + 30000;
while (core.mv_state.get() !== STATE_ENCRYPTED) {
  if (Date.now() >= deadline) {
    throw new Error(`Timed out waiting for encrypted transport (state ${core.mv_state.get()})`);
  }
  const data = await adapter.zif_oassh_socket$read({
    iv_timeout_seconds: new abap.types.Integer().set(30),
  });
  if (data.get() === "") {
    if ((await adapter.zif_oassh_socket$is_closed()).get() === "X") {
      throw new Error("OpenSSH closed before NEWKEYS");
    }
    continue;
  }
  try {
    await core.process_inbound({iv_data: data});
  } catch (error) {
    if (debug) dumpKexDiagnostics();
    throw error;
  }
  if (debug) console.error(`client state ${core.mv_state.get()}`);
}
await adapter.zif_oassh_socket$close();
console.log("encrypted transport established");
