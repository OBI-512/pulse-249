import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiFetch } from "../../api/client";
import { useReferenceData } from "./useReferenceData";

vi.mock("../../api/client", () => ({
  apiFetch: vi.fn(),
}));

const apiFetchMock = vi.mocked(apiFetch);

function renderReferenceData(permissions: string[]) {
  return renderHook(() => useReferenceData({
    token: "restricted-token",
    permissions,
    page: "overview",
    onError: vi.fn(),
  }));
}

beforeEach(() => {
  apiFetchMock.mockReset();
  apiFetchMock.mockResolvedValue([]);
});

describe("reference-data read authorization", () => {
  it("does not request /networks for a restricted overview user without network.read", async () => {
    const permissions = ["device.read", "topology.read"];
    const { result } = renderReferenceData(permissions);

    await act(async () => {
      await result.current.fetchCore("restricted-token", permissions);
      await result.current.loadNetworks();
    });

    expect(apiFetchMock).toHaveBeenCalledWith("/devices/types", {}, "restricted-token");
    expect(apiFetchMock.mock.calls.some(([path]) => String(path).startsWith("/networks"))).toBe(false);
  });

  it("does not treat geo.read as permission to call the network.read endpoint", async () => {
    const permissions = ["device.read", "geo.read"];
    const { result } = renderReferenceData(permissions);

    await act(async () => {
      await result.current.fetchCore("restricted-token", permissions);
      await result.current.loadNetworks();
    });

    expect(apiFetchMock.mock.calls.some(([path]) => String(path).startsWith("/networks"))).toBe(false);
  });

  it("loads /networks when network.read is granted", async () => {
    const permissions = ["device.read", "network.read"];
    const { result } = renderReferenceData(permissions);

    await act(async () => {
      await result.current.fetchCore("restricted-token", permissions);
    });

    expect(apiFetchMock.mock.calls.some(([path]) => String(path).startsWith("/networks?"))).toBe(true);
  });
});
