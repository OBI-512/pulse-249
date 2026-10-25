import { describe, expect, it, vi } from "vitest";
import { buildDeviceAccessMenuItems, type DeviceAccessCapabilities } from "./deviceAccess";
import devicePageSource from "../pages/DevicePage.tsx?raw";
import topologyPageSource from "../pages/TopologyPage.tsx?raw";
import liveNodeSource from "../features/topology/LiveDeviceNode.tsx?raw";
import lazyTopologySource from "../components/topology/LazyTopologyHierarchy.tsx?raw";

const base: DeviceAccessCapabilities = {
  device_id: "device-1",
  secure_web: { available: false, ready: false, reason_code: null },
  ssh: { available: false, ready: false, reason_code: null },
  telnet: { available: false, ready: false, reason_code: null },
};

describe("unified device access menu", () => {
  it("shows only the access methods that are actually available", () => {
    const items = buildDeviceAccessMenuItems({
      capabilities: {
        ...base,
        secure_web: { available: true, ready: true, reason_code: null },
        ssh: { available: true, ready: false, reason_code: "SSH_HOST_KEY_TRUST_REQUIRED" },
      },
      loading: false,
      onSecureWeb: vi.fn(),
      onSsh: vi.fn(),
      onTelnet: vi.fn(),
    });
    expect(items.map((item) => item.label)).toEqual(["Secure GUI", "SSH Terminal"]);
  });

  it("keeps enabled-but-not-ready SSH visible but fail-closed", () => {
    const items = buildDeviceAccessMenuItems({
      capabilities: {
        ...base,
        secure_web: { available: true, ready: true, reason_code: null },
        ssh: { available: true, ready: false, reason_code: "SSH_ACCESS_TEMPLATE_INCOMPLETE" },
      },
      loading: false,
      onSecureWeb: vi.fn(),
      onSsh: vi.fn(),
      onTelnet: vi.fn(),
    });
    expect(items.map((item) => item.label)).toEqual(["Secure GUI", "SSH Terminal (not ready)"]);
    expect(items[1].disabled).toBe(true);
  });

  it("keeps SSH host-trust onboarding actionable", () => {
    const items = buildDeviceAccessMenuItems({
      capabilities: {
        ...base,
        ssh: { available: true, ready: false, reason_code: "SSH_HOST_KEY_TRUST_REQUIRED" },
      },
      loading: false,
      onSecureWeb: vi.fn(),
      onSsh: vi.fn(),
      onTelnet: vi.fn(),
    });
    expect(items[0].label).toBe("SSH Terminal");
    expect(items[0].disabled).not.toBe(true);
  });

  it("shows a bounded loading placeholder while one interacted device is being resolved", () => {
    const items = buildDeviceAccessMenuItems({
      capabilities: undefined,
      loading: true,
      onSecureWeb: vi.fn(),
      onSsh: vi.fn(),
      onTelnet: vi.fn(),
    });
    expect(items).toHaveLength(1);
    expect(items[0].label).toContain("Checking remote access");
    expect(items[0].disabled).toBe(true);
  });

  it("renders the Inventory context menu through the document body and clamps it to the viewport", () => {
    expect(devicePageSource).toContain('import { createPortal } from "react-dom";');
    expect(devicePageSource).toContain("createPortal(<div");
    expect(devicePageSource).toContain("document.body)");
    expect(devicePageSource).toContain("window.innerWidth - rect.width - margin");
    expect(devicePageSource).toContain("window.innerHeight - rect.height - margin");
    expect(devicePageSource).toContain('transform:"none"');
  });

  it("removes normal direct-GUI launch shortcuts from device and topology surfaces", () => {
    for (const source of [devicePageSource, topologyPageSource, liveNodeSource, lazyTopologySource]) {
      expect(source).not.toContain("Open management GUI");
      expect(source).not.toContain("Direct GUI");
      expect(source).not.toContain("openManagementGui(");
    }
  });
});