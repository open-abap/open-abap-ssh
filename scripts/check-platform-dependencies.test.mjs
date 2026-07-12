import assert from "node:assert/strict";
import test from "node:test";

import { findPlatformDependencyViolations } from "./check-platform-dependencies.mjs";

test("allows the documented portable digest dependency in its adapter", () => {
  const violations = findPlatformDependencyViolations([
    {
      name: "zcl_oassh_sha256.clas.abap",
      source: "cl_abap_message_digest=>calculate_hash_for_raw( ).",
    },
    {
      name: "zcl_oassh_sha512.clas.abap",
      source: "cl_abap_message_digest=>calculate_hash_for_raw( ).",
    },
  ]);

  assert.deepEqual(violations, []);
});

test("allows APC dependencies only in the APC socket adapter", () => {
  const violations = findPlatformDependencyViolations([{
    name: "zcl_oassh_socket_apc.clas.abap",
    source: [
      "INTERFACES if_apc_wsp_event_handler.",
      "DATA frame TYPE apc_tcp_frame.",
      "cl_apc_tcp_client_manager=>create( ).",
    ].join("\n"),
  }]);

  assert.deepEqual(violations, []);
});

test("rejects a SAP dependency outside its approved file", () => {
  const violations = findPlatformDependencyViolations([{
    name: "zcl_oassh_transport.clas.abap",
    source: "cl_abap_message_digest=>calculate_hash_for_raw( ).",
  }]);

  assert.deepEqual(violations, [{
    file: "zcl_oassh_transport.clas.abap",
    line: 1,
    reference: "cl_abap_message_digest",
  }]);
});

test("rejects a SAP interface used as a declared dependency", () => {
  const violations = findPlatformDependencyViolations([{
    name: "zcl_oassh_transport.clas.abap",
    source: "DATA client TYPE REF TO if_apc_wsp_client.",
  }]);

  assert.deepEqual(violations, [{
    file: "zcl_oassh_transport.clas.abap",
    line: 1,
    reference: "if_apc_wsp_client",
  }]);
});

test("rejects a SAP exception used in a raising declaration", () => {
  const violations = findPlatformDependencyViolations([{
    name: "zcl_oassh_transport.clas.abap",
    source: "METHODS run RAISING cx_sy_file_open.",
  }]);

  assert.deepEqual(violations, [{
    file: "zcl_oassh_transport.clas.abap",
    line: 1,
    reference: "cx_sy_file_open",
  }]);
});

test("ignores testclasses, comments, and text literals", () => {
  const violations = findPlatformDependencyViolations([
    {
      name: "zcl_example.clas.testclasses.abap",
      source: "cl_abap_unit_assert=>assert_equals( ).",
    },
    {
      name: "zcl_example.clas.abap",
      source: [
        "* cl_forbidden=>call( ).",
        "DATA(text) = 'cl_forbidden=>call( )'. \" cl_also_forbidden=>call( )",
        "DATA(text2) = `cx_forbidden`.",
        "DATA(text3) = |if_forbidden|.",
        "method( if_parameter = value ).",
      ].join("\n"),
    },
  ]);

  assert.deepEqual(violations, []);
});

test("checks executable expressions embedded in string templates", () => {
  const violations = findPlatformDependencyViolations([{
    name: "zcl_example.clas.abap",
    source: "DATA(text) = |result: { cl_forbidden=>call( ) }|.",
  }]);

  assert.deepEqual(violations, [{
    file: "zcl_example.clas.abap",
    line: 1,
    reference: "cl_forbidden",
  }]);
});
