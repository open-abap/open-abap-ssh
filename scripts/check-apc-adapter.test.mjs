import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL(
  "../src/platform/zcl_oassh_socket_apc.clas.abap",
  import.meta.url,
), "utf8");

function methodBody(name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const match = source.match(new RegExp(
    `METHOD\\s+${escaped}\\.([\\s\\S]*?)ENDMETHOD\\.`,
    "u",
  ));
  assert.ok(match, `missing APC method ${name}`);
  return match[1];
}

for (const method of [
  "if_apc_wsp_event_handler~on_open",
  "if_apc_wsp_event_handler~on_message",
]) {
  test(`${method} propagates error completion`, () => {
    const body = methodBody(method);
    const caught = body.match(/CATCH\s+cx_root\s+INTO\s+lx_error\.([\s\S]*?)ENDTRY\./u);
    assert.ok(caught, `missing catch block in ${method}`);
    assert.match(caught[1], /mi_handler->on_error\(\s*\)\./u);
    assert.match(
      caught[1],
      /mv_complete\s*=\s*mi_handler->is_complete\(\s*\)\./u,
    );
  });
}

test("zif_oassh_socket~send emits one complete binary frame", () => {
  const body = methodBody("zif_oassh_socket~send");
  assert.match(body, /li_message->set_binary\(\s*iv_data\s*\)\./u);
  assert.doesNotMatch(body, /\bDO\b/u);
  assert.equal(
    [...body.matchAll(/li_message_manager->send\(\s*li_message\s*\)\./gu)].length,
    1,
  );
});
