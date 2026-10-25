import { describe, expect, it } from "vitest";
import panelSource from "./DeviceAccessTemplatesPanel.tsx?raw";
import accessHookSource from "../../hooks/useDeviceAccessActions.ts?raw";

describe("device Access Template SSH enablement", () => {
  it("keeps launch controls out of the Access Template editor after unification", () => {
    expect(panelSource).not.toContain("openWebSshWindow");
    expect(panelSource).not.toContain("openSecureWebGuiWindow");
    expect(panelSource).not.toContain("openWebTelnetWindow");
    expect(panelSource).toContain("unified Remote access section");
  });

  it("keeps already-ready SSH devices idempotent in the shared controller", () => {
    expect(accessHookSource).toContain('`/devices/${device.id}/remote-access`');
    expect(accessHookSource).toContain("if (status.ready) return true;");
  });

  it("promotes a previously trusted matching host key into explicit Web SSH enablement", () => {
    expect(accessHookSource).toContain('if (discovery.trust_state === "MATCH")');
    expect(accessHookSource).toContain('action: "TRUST_HOST_KEY"');
    expect(accessHookSource).toContain("expected_fingerprint: discovery.fingerprint");
    expect(accessHookSource).toContain("replace_existing: false");
    expect(accessHookSource).toContain("SSH host key verified and Web SSH enabled for this device.");
  });

  it("still requires explicit confirmation for new or changed host keys", () => {
    expect(accessHookSource).toContain('const replacing = discovery.trust_state === "MISMATCH"');
    expect(accessHookSource).toContain("const approved = await dialog.confirm");
    expect(accessHookSource).toContain("if (!approved) return false;");
  });
});