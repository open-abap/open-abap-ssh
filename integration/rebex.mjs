// Runs the integration scenarios against the public Rebex test server
// (https://test.rebex.net), an independent non-OpenSSH implementation.
// The server is read-only and its virtual shell lacks printf, so exec
// uses echo, which appends a trailing newline to stdout.
import {spawnSync} from "node:child_process";
import path from "node:path";
import {fileURLToPath} from "node:url";

const dir = path.dirname(fileURLToPath(import.meta.url));
const env = {
  ...process.env,
  OASSH_HOST: process.env.OASSH_HOST ?? "test.rebex.net",
  OASSH_PORT: process.env.OASSH_PORT ?? "22",
  OASSH_USER: process.env.OASSH_USER ?? "demo",
  OASSH_PASSWORD: process.env.OASSH_PASSWORD ?? "password",
  OASSH_COMMAND: process.env.OASSH_COMMAND ?? "echo open-abap-ssh",
  OASSH_EXPECTED: process.env.OASSH_EXPECTED ?? "open-abap-ssh\n",
  OASSH_EXPECT_STRICT_KEX: process.env.OASSH_EXPECT_STRICT_KEX ?? "1",
};

for (const script of ["transport.mjs", "auth.mjs", "exec.mjs"]) {
  console.log(`--- ${script} against ${env.OASSH_HOST}:${env.OASSH_PORT} ---`);
  const result = spawnSync(process.execPath, [path.join(dir, script)], {env, stdio: "inherit"});
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
