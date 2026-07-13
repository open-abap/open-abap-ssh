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
  OASSH_SFTP_PATH: process.env.OASSH_SFTP_PATH ?? "/pub/example/readme.txt",
  OASSH_SFTP_STAT_PATH: process.env.OASSH_SFTP_STAT_PATH ?? "/pub/example/readme.txt",
  OASSH_SFTP_STAT_SIZE_HEX: process.env.OASSH_SFTP_STAT_SIZE_HEX ?? "000000000000017B",
  OASSH_SFTP_EXPECTED_HEX: process.env.OASSH_SFTP_EXPECTED_HEX ??
    "57656C636F6D6520746F20746573742E72656265782E6E6574210D0A0D0A596F752061726520636F6E6E656374656420746F20616E20465450206F72205346545020736572766572207573656420666F722074657374696E6720707572706F7365730D0A6279205265626578204654502F53534C206F7220526562657820534654502073616D706C6520636F64652E204F6E6C7920726561642061636365737320697320616C6C6F7765642E0D0A0D0A466F7220696E666F726D6174696F6E2061626F7574205265626578204654502F53534C2C205265626578205346545020616E64206F74686572205265626578206C69627261726965730D0A666F72202E4E45542C20706C65617365207669736974206F757220776562736974652061742068747470733A2F2F7777772E72656265782E6E65742F0D0A0D0A466F7220666565646261636B20616E6420737570706F72742C20636F6E7461637420737570706F72744072656265782E6E65740D0A0D0A5468616E6B73210D0A",
};

for (const script of ["transport.mjs", "auth.mjs", "exec.mjs", "sftp.mjs", "sftp-stat.mjs"]) {
  console.log(`--- ${script} against ${env.OASSH_HOST}:${env.OASSH_PORT} ---`);
  const result = spawnSync(process.execPath, [path.join(dir, script)], {env, stdio: "inherit"});
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
