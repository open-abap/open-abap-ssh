import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const SOURCE_DIRECTORY = fileURLToPath(new URL("../src", import.meta.url));

const PORTABLE_RUNTIME_TYPES = new Set([
  "cx_root",
  "cx_static_check",
]);

const ALLOWED_BY_FILE = new Map([
  ["zcl_oassh_ascii.clas.abap", new Set([
    "cl_abap_codepage",
  ])],
  ["zcl_oassh_hmac.clas.abap", new Set([
    "cl_abap_hmac",
    "cx_abap_message_digest",
  ])],
  ["zcl_oassh_sha256.clas.abap", new Set([
    "cl_abap_message_digest",
    "cx_abap_message_digest",
  ])],
  ["zcl_oassh_socket_apc.clas.abap", new Set([
    "apc_tcp_frame",
    "cl_apc_tcp_client_manager",
    "cx_apc_error",
    "if_apc_tcp_frame_types",
    "if_apc_wsp_client",
    "if_apc_wsp_event_handler",
    "if_apc_wsp_message",
    "if_apc_wsp_message_manager",
  ])],
]);

const PREFIXED_REFERENCE = /\b(?:cl|cx|if)_[a-z0-9_]+\b(?!\s*=(?!>))/giu;
const NON_PREFIXED_REFERENCE = /\bapc_tcp_frame\b/giu;

function stripStringsAndComments(line) {
  if (/^\s*\*/u.test(line)) {
    return "";
  }

  let result = "";
  let delimiter;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];

    if (delimiter !== undefined) {
      if (delimiter === "|" && character === "\\") {
        index += 1;
      } else if (character === delimiter && line[index + 1] === delimiter) {
        index += 1;
      } else if (character === delimiter) {
        delimiter = undefined;
      }
      result += " ";
    } else if (["'", "`", "|"].includes(character)) {
      delimiter = character;
      result += " ";
    } else if (character === '"') {
      break;
    } else {
      result += character;
    }
  }

  return result;
}

function referencesInLine(line) {
  const code = stripStringsAndComments(line);
  return new Set([
    ...(code.match(PREFIXED_REFERENCE) ?? []),
    ...(code.match(NON_PREFIXED_REFERENCE) ?? []),
  ].map((reference) => reference.toLowerCase()));
}

export function findPlatformDependencyViolations(files) {
  const violations = [];

  for (const { name, source } of files) {
    if (name.endsWith(".testclasses.abap")) {
      continue;
    }

    const allowed = ALLOWED_BY_FILE.get(name) ?? new Set();
    const lines = source.split(/\r?\n/u);

    lines.forEach((line, index) => {
      for (const reference of referencesInLine(line)) {
        if (!PORTABLE_RUNTIME_TYPES.has(reference) && !allowed.has(reference)) {
          violations.push({
            file: name,
            line: index + 1,
            reference,
          });
        }
      }
    });
  }

  return violations;
}

async function checkRepository() {
  const names = (await readdir(SOURCE_DIRECTORY))
    .filter((name) => name.endsWith(".abap"));
  const files = await Promise.all(names.map(async (name) => ({
    name,
    source: await readFile(path.join(SOURCE_DIRECTORY, name), "utf8"),
  })));
  const violations = findPlatformDependencyViolations(files);

  if (violations.length > 0) {
    for (const violation of violations) {
      console.error(
        `${violation.file}:${violation.line}: SAP dependency ${violation.reference} is not allowed here`,
      );
    }
    process.exitCode = 1;
  } else {
    console.log("platform dependency boundary passed");
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await checkRepository();
}
