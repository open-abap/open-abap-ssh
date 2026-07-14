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
  "if_apc_wsp_event_handler~on_close",
  "if_apc_wsp_event_handler~on_error",
]) {
  test(`${method} marks the transport closed`, () => {
    assert.match(methodBody(method), /mv_closed\s*=\s*abap_true\./u);
  });
}

test("if_apc_wsp_event_handler~on_message buffers and treats frame errors as terminal", () => {
  const body = methodBody("if_apc_wsp_event_handler~on_message");
  assert.match(body, /mv_buffer\s*=\s*mv_buffer\s*&&\s*i_message->get_binary\(\s*\)\./u);
  const caught = body.match(/CATCH\s+cx_root\s+INTO\s+lx_error\.([\s\S]*?)ENDTRY\./u);
  assert.ok(caught, "missing catch block in on_message");
  assert.match(caught[1], /mv_closed\s*=\s*abap_true\./u);
});

test("zif_oassh_socket~read waits for push channels until data or close", () => {
  const body = methodBody("zif_oassh_socket~read");
  assert.match(
    body,
    /WAIT FOR PUSH CHANNELS\s+UNTIL mv_buffer IS NOT INITIAL OR mv_closed = abap_true\s+UP TO iv_timeout_seconds SECONDS\./u,
  );
  assert.match(body, /CLEAR mv_buffer\./u);
});

test("zif_oassh_socket~send emits one complete binary frame", () => {
  const body = methodBody("zif_oassh_socket~send");
  assert.match(body, /li_message->set_binary\(\s*iv_data\s*\)\./u);
  assert.doesNotMatch(body, /\bDO\b/u);
  assert.equal(
    [...body.matchAll(/li_message_manager->send\(\s*li_message\s*\)\./gu)].length,
    1,
  );
});
