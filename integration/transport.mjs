import net from "node:net";
import crypto from "node:crypto";

await import("../output/init.mjs");
for (const module of [
  "zcl_oassh_ascii.clas.mjs",
  "zcl_oassh_stream.clas.mjs",
  "zcl_oassh_sha256.clas.mjs",
  "zcl_oassh_hmac.clas.mjs",
  "zcl_oassh_bigint.clas.mjs",
  "zcl_oassh_x25519.clas.mjs",
  "zcl_oassh_kdf.clas.mjs",
  "zcl_oassh_rsa.clas.mjs",
  "zcl_oassh_aes.clas.mjs",
  "zcl_oassh_ctr.clas.mjs",
  "zcl_oassh_packet.clas.mjs",
  "zcl_oassh_message_20.clas.mjs",
  "zcl_oassh_message_21.clas.mjs",
  "zcl_oassh_message_ecdh_30.clas.mjs",
  "zcl_oassh_message_ecdh_31.clas.mjs",
  "zcl_oassh_message_5.clas.mjs",
  "zcl_oassh_message_6.clas.mjs",
  "zcl_oassh_message_50.clas.mjs",
  "zcl_oassh_message_51.clas.mjs",
  "zcl_oassh_message_52.clas.mjs",
  "zcl_oassh_message_53.clas.mjs",
  "zcl_oassh_transport.clas.mjs",
  "zcl_oassh.clas.mjs",
]) {
  await import(`../output/${module}`);
}

const host = process.argv[2] ?? process.env.OASSH_HOST ?? "127.0.0.1";
const port = Number(process.argv[3] ?? process.env.OASSH_PORT ?? "2222");
const debug = process.env.OASSH_DEBUG === "1" || process.argv.includes("--debug");

let handler;
let socket;
let callbackQueue = Promise.resolve();
const receivedChunks = [];
const sentChunks = [];
const randomCalls = [];
let resolveEncrypted;
let rejectEncrypted;
const encrypted = new Promise((resolve, reject) => {
  resolveEncrypted = resolve;
  rejectEncrypted = reject;
});

const random = {
  async zif_oassh_random$bytes({iv_length}) {
    const value = crypto.randomBytes(iv_length.get());
    randomCalls.push(value);
    return new abap.types.XString().set(value.toString("hex").toUpperCase());
  },
};
const hostVerifier = {
  async zif_oassh_host_verifier$verify() {
    return abap.builtin.abap_true;
  },
};

const socketAdapter = {
  async zif_oassh_socket$set_handler({ii_handler}) {
    handler = ii_handler;
  },
  async zif_oassh_socket$connect() {
    socket = net.createConnection({host, port});
    socket.once("connect", () => {
      if (debug) console.error("connected");
      callbackQueue = callbackQueue.then(() => handler.get().zif_oassh_socket_handler$on_open());
    });
    socket.on("data", data => {
      receivedChunks.push(data);
      if (debug) console.error(`received ${data.length} bytes: ${data.subarray(0, 40).toString("hex")}`);
      callbackQueue = callbackQueue
        .then(() => handler.get().zif_oassh_socket_handler$on_message({
          iv_data: new abap.types.XString().set(data.toString("hex").toUpperCase()),
        }))
        .then(() => {
          const state = handler.get().FRIENDS_ACCESS_INSTANCE.mv_state.get();
          if (debug) console.error(`client state ${state}`);
          if (state === 3) resolveEncrypted();
        })
        .catch(error => {
          if (debug) {
            const transport = handler.get().FRIENDS_ACCESS_INSTANCE.mo_transport.get();
            console.error(`exchange hash ${transport.FRIENDS_ACCESS_INSTANCE.mv_h.get()}`);
            const packet = receivedChunks.at(-1);
            if (packet?.length > 10 && packet[5] === 31) {
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
              const h = Buffer.from(transport.FRIENDS_ACCESS_INSTANCE.mv_h.get(), "hex");
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
          }
          rejectEncrypted(error);
        });
    });
    socket.once("error", rejectEncrypted);
    socket.once("close", () => rejectEncrypted(new Error("OpenSSH closed before NEWKEYS")));
  },
  async zif_oassh_socket$send({iv_data}) {
    const data = Buffer.from(iv_data.get(), "hex");
    sentChunks.push(data);
    if (debug) console.error(`sending ${data.length} bytes`);
    socket.write(data);
  },
  async zif_oassh_socket$close() {
    socket.end();
  },
  async zif_oassh_socket$wait() {
    return;
  },
};

const socketRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET"}).set(socketAdapter);
const randomRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_RANDOM"}).set(random);
const verifierRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_HOST_VERIFIER"}).set(hostVerifier);
const client = await new abap.Classes.ZCL_OASSH().constructor_({
  ii_socket: socketRef,
  ii_random: randomRef,
  ii_host_verifier: verifierRef,
  iv_user: new abap.types.String().set(process.env.OASSH_USER ?? "test"),
  iv_password: new abap.types.String().set(process.env.OASSH_PASSWORD ?? "test"),
});
const clientRef = new abap.types.ABAPObject({qualifiedName: "ZIF_OASSH_SOCKET_HANDLER"}).set(client);
await socketAdapter.zif_oassh_socket$set_handler({ii_handler: clientRef});
await socketAdapter.zif_oassh_socket$connect();

const timeout = new Promise((_, reject) => {
  setTimeout(() => {
    const state = handler?.get().FRIENDS_ACCESS_INSTANCE.mv_state.get();
    reject(new Error(`Timed out waiting for encrypted transport (state ${state})`));
  }, 30000);
});
await Promise.race([encrypted, timeout]);
socket.end();
console.log("encrypted transport established");
