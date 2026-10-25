import { act, renderHook, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiFetch } from "../../api/client";
import type { Candidate, SortState } from "../../types";
import { useCandidateWorkspace } from "./useCandidateWorkspace";

vi.mock("../../api/client", () => ({
  apiFetch: vi.fn(),
}));

vi.mock("../../components/common/DialogSystem", () => ({
  useDialog: () => ({ confirm: vi.fn().mockResolvedValue(true) }),
}));

const apiFetchMock = vi.mocked(apiFetch);
const firstCandidate = {
  id: "candidate-1",
  ip_address: "192.0.2.10",
  state: "NEW",
  created_at: "2026-09-01T00:00:00Z",
} as Candidate;
const secondCandidate = {
  ...firstCandidate,
  id: "candidate-2",
  ip_address: "192.0.2.11",
} as Candidate;

function candidateListCalls() {
  return apiFetchMock.mock.calls.filter(([path]) => String(path).startsWith("/device-candidates?"));
}

function auditCalls() {
  return apiFetchMock.mock.calls.filter(([path]) => String(path).endsWith("/audit"));
}

function renderCandidateWorkspace(strictMode = false) {
  const render = () => useCandidateWorkspace({
    token: "candidate-token",
    permissions: ["candidate.read", "candidate.review"],
    active: true,
    types: [],
    setBusy: vi.fn(),
    clearAlerts: vi.fn(),
    setError: vi.fn(),
    setMessage: vi.fn(),
    onError: vi.fn(),
    onReferenceRefresh: vi.fn().mockResolvedValue(undefined),
    onDevicesChanged: vi.fn().mockResolvedValue(undefined),
  });
  return renderHook(render, strictMode ? { wrapper: StrictMode } : undefined);
}

beforeEach(() => {
  apiFetchMock.mockReset();
  apiFetchMock.mockImplementation(async (path) => {
    if (String(path).endsWith("/audit")) return [];
    if (String(path).startsWith("/device-candidates?")) {
      return { items: [firstCandidate, secondCandidate], count: 2 };
    }
    throw new Error(`Unexpected request: ${String(path)}`);
  });
});

describe("Candidate Review request lifecycle", () => {
  it("stays bounded through Strict Mode selection and idle time", async () => {
    vi.useFakeTimers();
    try {
      const { result } = renderCandidateWorkspace(true);
      await act(async () => { await Promise.resolve(); });
      expect(candidateListCalls()).toHaveLength(2);

      await act(async () => { await result.current.selectCandidate(firstCandidate); });
      await act(async () => {
        vi.advanceTimersByTime(30_000);
        await Promise.resolve();
      });

      expect(candidateListCalls()).toHaveLength(2);
      expect(auditCalls().map(([path]) => path)).toEqual(["/device-candidates/candidate-1/audit"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not poll the candidate list while the page is idle", async () => {
    vi.useFakeTimers();
    try {
      renderCandidateWorkspace();
      await act(async () => { await Promise.resolve(); });
      expect(candidateListCalls()).toHaveLength(1);

      await act(async () => {
        vi.advanceTimersByTime(30_000);
        await Promise.resolve();
      });
      expect(candidateListCalls()).toHaveLength(1);
      expect(auditCalls()).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("loads the list once, stays idle, and selection only loads the selected audit", async () => {
    const { result, rerender } = renderCandidateWorkspace();

    await waitFor(() => expect(candidateListCalls()).toHaveLength(1));

    rerender();
    await act(async () => { await Promise.resolve(); });
    expect(candidateListCalls()).toHaveLength(1);

    await act(async () => { await result.current.selectCandidate(firstCandidate); });
    expect(candidateListCalls()).toHaveLength(1);
    expect(auditCalls().map(([path]) => path)).toEqual(["/device-candidates/candidate-1/audit"]);

    rerender();
    await act(async () => { await Promise.resolve(); });
    expect(candidateListCalls()).toHaveLength(1);
    expect(auditCalls()).toHaveLength(1);

    await act(async () => { await result.current.selectCandidate(secondCandidate); });
    expect(candidateListCalls()).toHaveLength(1);
    expect(auditCalls().map(([path]) => path)).toEqual([
      "/device-candidates/candidate-1/audit",
      "/device-candidates/candidate-2/audit",
    ]);
  });

  it("reloads for legitimate filter, sort, and page changes", async () => {
    const { result } = renderCandidateWorkspace();
    await waitFor(() => expect(candidateListCalls()).toHaveLength(1));

    act(() => { result.current.setFilter("APPROVED"); });
    await waitFor(() => expect(candidateListCalls()).toHaveLength(2));
    expect(String(candidateListCalls()[1][0])).toContain("state=APPROVED");

    act(() => {
      result.current.setSort({ key: "ip_address", direction: "asc" } as SortState);
    });
    await waitFor(() => expect(candidateListCalls()).toHaveLength(3));
    expect(String(candidateListCalls()[2][0])).toContain("sort_by=ip_address");
    expect(String(candidateListCalls()[2][0])).toContain("sort_direction=asc");

    act(() => { result.current.setPage(2); });
    await waitFor(() => expect(candidateListCalls()).toHaveLength(4));
    expect(String(candidateListCalls()[3][0])).toContain("offset=50");
  });
});
