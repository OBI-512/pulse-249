import { describe, expect, it } from "vitest";
import { canRestoreSnapshot, coerceParameterValue, isActiveConfigurationOperation, parameterDefinitions, publishedVersions, type ConfigurationFunction, type ConfigurationSnapshot, type ConfigurationTemplateDetail } from "./model";

const snapshot: ConfigurationSnapshot = {
  id:"s", device_id:"d", template_version_id:"v1", snapshot_kind:"CAPTURE", adapter_key:"generic.ssh_cli",
  artifact_status:"READY", artifact_sha256:null, plaintext_sha256:null, normalized_sha256:"abc", artifact_size_bytes:10,
  is_restorable:true, created_at:"2026-09-07T00:00:00Z",
};

it("allows restore only for READY restorable snapshot bound to exact version", () => {
  expect(canRestoreSnapshot(snapshot, "v1")).toBe(true);
  expect(canRestoreSnapshot({ ...snapshot, template_version_id:"v2" }, "v1")).toBe(false);
  expect(canRestoreSnapshot({ ...snapshot, artifact_status:"FAILED" }, "v1")).toBe(false);
  expect(canRestoreSnapshot({ ...snapshot, is_restorable:false }, "v1")).toBe(false);
});

it("recognizes only nonterminal operation states as active", () => {
  expect(isActiveConfigurationOperation("QUEUED")).toBe(true);
  expect(isActiveConfigurationOperation("RUNNING")).toBe(true);
  expect(isActiveConfigurationOperation("ROLLING_BACK")).toBe(true);
  expect(isActiveConfigurationOperation("SUCCEEDED")).toBe(false);
  expect(isActiveConfigurationOperation("ROLLBACK_FAILED")).toBe(false);
});

it("selects published versions newest first", () => {
  const detail = { versions:[
    { version:{ id:"1", version_number:1, status:"RETIRED" }, functions:[] },
    { version:{ id:"2", version_number:2, status:"PUBLISHED" }, functions:[] },
    { version:{ id:"3", version_number:3, status:"PUBLISHED" }, functions:[] },
  ] } as unknown as ConfigurationTemplateDetail;
  expect(publishedVersions(detail).map((entry) => entry.version.id)).toEqual(["3", "2"]);
});

it("reads parameter schema and preserves typed values", () => {
  const fn = { parameter_schema:{ parameters:[{ name:"vlan", value_type:"VLAN_ID" }, { name:"enabled", value_type:"BOOLEAN" }] } } as unknown as ConfigurationFunction;
  expect(parameterDefinitions(fn)).toHaveLength(2);
  expect(coerceParameterValue({ name:"vlan", value_type:"VLAN_ID" }, "123")).toBe(123);
  expect(coerceParameterValue({ name:"enabled", value_type:"BOOLEAN" }, "true")).toBe(true);
});
