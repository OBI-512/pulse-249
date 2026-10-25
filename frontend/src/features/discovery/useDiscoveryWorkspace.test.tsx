import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiFetch } from "../../api/client";
import { useDiscoveryWorkspace } from "./useDiscoveryWorkspace";

vi.mock("../../api/client", () => ({ apiFetch: vi.fn() }));

const apiFetchMock = vi.mocked(apiFetch);

function renderWorkspace(setError = vi.fn()) {
  return renderHook(() => useDiscoveryWorkspace({
    token: "discovery-token",
    permissions: ["discovery.read", "discovery.run"],
    active: false,
    setBusy: vi.fn(),
    clearAlerts: vi.fn(),
    setError,
    setMessage: vi.fn(),
    onError: vi.fn(),
    confirm: vi.fn().mockResolvedValue(true),
    onCandidatesChanged: vi.fn().mockResolvedValue(undefined),
  }));
}

function discoveryPayload() {
  const call = apiFetchMock.mock.calls.find(([path]) => path === "/discovery/run");
  expect(call).toBeDefined();
  return JSON.parse(String(call?.[1]?.body));
}

beforeEach(() => {
  apiFetchMock.mockReset();
  apiFetchMock.mockImplementation(async (path) => {
    if (path === "/discovery/run") return { job_id: "job-1", status: "COMPLETED", results: [] };
    if (String(path).startsWith("/discovery/jobs/page?")) return { items: [], total: 0 };
    throw new Error(`Unexpected request: ${String(path)}`);
  });
});

describe("HTTP/HTTPS discovery port input", () => {
  it("sends independent custom HTTP and HTTPS ports", async () => {
    const { result } = renderWorkspace();
    act(() => {
      result.current.setIp("192.0.2.10");
      result.current.setMethods(["HTTP", "HTTPS"]);
      result.current.setHttpPort("8080");
      result.current.setHttpsPort("8443");
    });

    await act(async () => { await result.current.run(); });

    expect(discoveryPayload()).toMatchObject({ http_port: 8080, https_port: 8443 });
  });

  it("sends null ports when the optional fields are blank", async () => {
    const { result } = renderWorkspace();
    act(() => {
      result.current.setIp("192.0.2.10");
      result.current.setMethods(["HTTP", "HTTPS"]);
    });

    await act(async () => { await result.current.run(); });

    expect(discoveryPayload()).toMatchObject({ http_port: null, https_port: null });
  });

  it.each(["0", "65536", "1.5"])("rejects invalid port %s before issuing a request", async (port) => {
    const setError = vi.fn();
    const { result } = renderWorkspace(setError);
    act(() => {
      result.current.setIp("192.0.2.10");
      result.current.setMethods(["HTTP"]);
      result.current.setHttpPort(port);
    });

    await act(async () => { await result.current.run(); });

    expect(apiFetchMock).not.toHaveBeenCalled();
    expect(setError).toHaveBeenCalledWith("HTTP port must be blank or an integer between 1 and 65535.");
  });
});
