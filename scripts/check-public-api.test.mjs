import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const publicSources = [
  "../src/zcl_oassh.clas.abap",
  "../src/zif_oassh_interactive_exec.intf.abap",
  "../src/zif_oassh_sftp_one_shot.intf.abap",
  "../src/zif_oassh_sftp_session.intf.abap",
  "../src/platform/zif_oassh_socket.intf.abap",
];

for (const relativePath of publicSources) {
  test(`${relativePath} exposes only the project exception`, async () => {
    const source = await readFile(new URL(relativePath, import.meta.url), "utf8");

    assert.doesNotMatch(source, /RAISING\s+cx_static_check\b/gu);
    assert.match(source, /RAISING\s+zcx_oassh_error\b/gu);
  });
}
