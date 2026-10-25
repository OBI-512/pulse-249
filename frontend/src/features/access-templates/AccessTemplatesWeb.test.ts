import { describe, expect, it } from "vitest";
import source from "./AccessTemplatesPanel.tsx?raw";
import deviceSource from "../../components/device/DeviceAccessTemplatesPanel.tsx?raw";
import accessActionsSource from "../../hooks/useDeviceAccessActions.ts?raw";
import remoteAccessSource from "../../utils/remoteAccess.ts?raw";


describe("WEB Access Templates and Secure GUI", () => {
  it("supports WEB as a first-class Access Template protocol", () => {
    expect(source).toContain('"SNMP" | "SSH" | "TELNET" | "WEB"');
    expect(source).toContain("<option>WEB</option>");
    expect(source).toContain('value="FORM_POST"');
    expect(source).toContain('value="HTTP_BASIC"');
    expect(source).toContain('value="HTTP_DIGEST"');
  });

  it("keeps Web transport and TLS device-specific", () => {
    expect(source).toContain('if (draft.protocol !== "WEB") settings.port = Number(draft.port);');
    expect(source).toContain("HTTP/HTTPS scheme, port, enablement, and TLS/certificate trust remain device-specific");
  });

  it("offers server-side form login without putting credentials into settings", () => {
    expect(source).toContain("web_login_page_path");
    expect(source).toContain("web_login_submit_path");
    expect(source).toContain("web_username_field");
    expect(source).toContain("web_password_field");
    expect(source).toContain('key: "username", label: "Web GUI username"');
    expect(source).toContain('key: "password", label: "Web GUI password"');
  });

  it("keeps WEB resolution in Access Templates and Secure GUI launch in unified Remote Access", () => {
    expect(deviceSource).toContain("/access-templates/effective/${device.id}/WEB");
    expect(deviceSource).toContain("credentials are never sent to the browser");
    expect(deviceSource).toContain("Use the unified Remote access section for Secure GUI");

    expect(accessActionsSource).toContain('"device.remote_access.web"');
    expect(accessActionsSource).toContain("openSecureWebGuiWindow");

    expect(remoteAccessSource).toContain("/devices/${deviceId}/remote-access/web-sessions");
    expect(remoteAccessSource).toContain("fttw-web-gui-launch");
  });
});