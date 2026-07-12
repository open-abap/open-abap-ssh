import {readFile, writeFile} from "node:fs/promises";

const path = new URL("../output/cl_abap_message_digest.clas.mjs", import.meta.url);
const source = await readFile(path, "utf8");
const needle = "abap.compare.eq(lv_algorithm, abap.CharacterFactory.get(6, 'sha256')));";
const replacement =
  "abap.compare.eq(lv_algorithm, abap.CharacterFactory.get(6, 'sha256')) || " +
  "abap.compare.eq(lv_algorithm, abap.CharacterFactory.get(6, 'sha512')));";

if (!source.includes(needle)) {
  throw new Error("open-abap digest runtime shape changed; SHA-512 adapter was not applied");
}
await writeFile(path, source.replaceAll(needle, replacement));
