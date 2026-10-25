import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ apiFetch: vi.fn() }));
vi.mock("../api/client", () => ({ apiFetch: mocks.apiFetch }));

import { openWebSshWindow } from "./remoteAccess";

class FakeBroadcastChannel {
  static sent: unknown[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  constructor(public name: string) {
    queueMicrotask(() => this.onmessage?.({ data:{ type:"ready" } } as MessageEvent));
  }
  postMessage(data: any) {
    FakeBroadcastChannel.sent.push(data);
    if (data?.type === "launch") queueMicrotask(() => this.onmessage?.({ data:{ type:"received" } } as MessageEvent));
  }
  close() {}
}

describe("openWebSshWindow", () => {
  beforeEach(() => {
    FakeBroadcastChannel.sent = [];
    mocks.apiFetch.mockReset();
    mocks.apiFetch.mockResolvedValue({
      session_id:"session-1",
      ticket:"one-time-secret-ticket",
      expires_at:"2026-08-30T00:00:00Z",
      websocket_path:"/ws/ssh",
    });
    vi.stubGlobal("BroadcastChannel", FakeBroadcastChannel);
    vi.spyOn(window, "open").mockReturnValue({ closed:false } as Window);
  });

  it("opens a new tab without putting the one-time ticket in the URL", async () => {
    await openWebSshWindow("session-token", "device-1", "Device One");
    const openedUrl = vi.mocked(window.open).mock.calls[0][0] as string;
    expect(openedUrl).toContain("/remote-ssh.html?channel=");
    expect(openedUrl).not.toContain("one-time-secret-ticket");
    expect(FakeBroadcastChannel.sent).toContainEqual(expect.objectContaining({ type:"launch", ticket:"one-time-secret-ticket" }));
    expect(mocks.apiFetch).toHaveBeenCalledWith(
      "/devices/device-1/remote-access/ssh-sessions",
      { method:"POST" },
      "session-token",
    );
  });
});
