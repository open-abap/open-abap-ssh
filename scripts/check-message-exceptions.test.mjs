import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const sourceDirectory = new URL("../src/", import.meta.url);

test("all SSH exceptions use native MESSAGE raises", async () => {
  const names = (await readdir(sourceDirectory, { recursive: true }))
    .filter((name) => name.endsWith(".abap"));
  const sources = await Promise.all(names.map((name) => readFile(
    new URL(name.replaceAll("\\", "/"), sourceDirectory),
    "utf8",
  )));
  const source = sources.join("\n");
  const raises = source.match(/RAISE EXCEPTION TYPE zcx_oassh_error\b/gu) ?? [];
  const messageRaises = source.match(
    /RAISE EXCEPTION TYPE zcx_oassh_error\s+MESSAGE\b/gu,
  ) ?? [];

  assert.ok(raises.length > 0, "expected typed SSH exception raises");
  assert.equal(messageRaises.length, raises.length);
  assert.doesNotMatch(source, /zcx_oassh_error=>raise\b/gu);
  assert.doesNotMatch(source, /zcx_oassh_error=>c_reason\b/gu);
});

test("ZOASSH defines every referenced message", async () => {
  const messageClass = await readFile(new URL("zoassh.msag.xml", sourceDirectory), "utf8");
  const numbers = [...messageClass.matchAll(/<MSGNR>(\d{3})<\/MSGNR>/gu)]
    .map((match) => match[1]);

  assert.deepEqual(numbers, [
    "001", "002", "003", "004", "005", "006", "007",
    "008", "009", "010", "011", "012", "013",
  ]);
});
