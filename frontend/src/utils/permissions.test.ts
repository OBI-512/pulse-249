import { describe, expect, it } from "vitest";
import { canAccessPage, hasPermission, PERMISSION } from "./permissions";

describe("permission helpers", () => {
  it("fails closed when a permission is absent", () => {
    expect(hasPermission([], PERMISSION.DEVICE_READ)).toBe(false);
    expect(canAccessPage("devices", [])).toBe(false);
  });

  it("keeps Candidate Review independent from geo.read", () => {
    expect(canAccessPage("candidates", [PERMISSION.CANDIDATE_READ])).toBe(true);
    expect(canAccessPage("candidates", [PERMISSION.GEO_READ])).toBe(false);
  });

  it("requires alarm.read for the alarm workspace", () => {
    expect(canAccessPage("alarms", [PERMISSION.ALARM_READ])).toBe(true);
    expect(canAccessPage("alarms", [PERMISSION.DEVICE_READ])).toBe(false);
  });

  it("requires maintenance.read for the maintenance workspace", () => {
    expect(canAccessPage("maintenance", [PERMISSION.MAINTENANCE_READ])).toBe(true);
    expect(canAccessPage("maintenance", [PERMISSION.NOTIFICATION_READ])).toBe(false);
    expect(canAccessPage("maintenance", [PERMISSION.DEVICE_READ])).toBe(false);
  });

  it("permits network workspace with either network.read or geo.read", () => {
    expect(canAccessPage("networks", [PERMISSION.NETWORK_READ])).toBe(true);
    expect(canAccessPage("networks", [PERMISSION.GEO_READ])).toBe(true);
  });
  it("permits Data & Reports for any Phase-D read surface only", () => {
    expect(canAccessPage("data-reporting", [PERMISSION.TELEMETRY_READ])).toBe(true);
    expect(canAccessPage("data-reporting", [PERMISSION.DATA_LIFECYCLE_READ])).toBe(true);
    expect(canAccessPage("data-reporting", [PERMISSION.DATA_EXCHANGE_READ])).toBe(true);
    expect(canAccessPage("data-reporting", [PERMISSION.REPORT_READ])).toBe(true);
    expect(canAccessPage("data-reporting", [PERMISSION.DEVICE_READ])).toBe(false);
  });

});
