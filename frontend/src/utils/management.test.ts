import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../api/client";
import { managementUrl, openManagementGui } from "./management";

vi.mock("../api/client", () => ({ apiFetch: vi.fn() }));

describe("management GUI resolution", () => {
  beforeEach(() => vi.clearAllMocks());

  it("prefers HTTPS when the inventory protocol is not itself a web protocol", () => {
    expect(managementUrl({ management_ip: "192.0.2.10", management_protocol: "SNMPV2C" })).toBe("https://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", management_protocol: "HTTPS" })).toBe("https://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", management_protocol: "HTTP" })).toBe("http://192.0.2.10");
  });

  it("uses configured web ports and omits protocol-default ports", () => {
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTP", web_port: null })).toBe("http://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTPS", web_port: null })).toBe("https://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTP", web_port: 80 })).toBe("http://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTPS", web_port: 443 })).toBe("https://192.0.2.10");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTP", web_port: 8080 })).toBe("http://192.0.2.10:8080");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTPS", web_port: 8443 })).toBe("https://192.0.2.10:8443");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTP", web_port: 1 })).toBe("http://192.0.2.10:1");
    expect(managementUrl({ management_ip: "192.0.2.10", web_scheme: "HTTPS", web_port: 65535 })).toBe("https://192.0.2.10:65535");
  });

  it("opens the backend-resolved management URL in the already-created tab", async () => {
    const replace = vi.fn();
    const close = vi.fn();
    const fakeTab = {
      opener: window,
      document: { title: "", body: { textContent: "" } },
      location: { replace },
      close,
    } as unknown as Window;
    vi.spyOn(window, "open").mockReturnValue(fakeTab);
    vi.mocked(apiFetch).mockResolvedValue({
      reachable: true,
      url: "https://192.0.2.20",
      status_code: 200,
      response_time_ms: 12,
      message: "resolved",
    });

    await expect(openManagementGui({ id: "dev-1", management_ip: "192.0.2.20", management_protocol: "SNMP" }, "token")).resolves.toBe(true);
    expect(apiFetch).toHaveBeenCalledWith("/devices/dev-1/test-accessibility", { method: "POST" }, "token");
    expect(replace).toHaveBeenCalledWith("https://192.0.2.20");
    expect(close).not.toHaveBeenCalled();
  });
});
