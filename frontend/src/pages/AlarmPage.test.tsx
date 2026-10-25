import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DialogProvider } from "../components/common/DialogSystem";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import type { AlarmRow } from "../types";
import { AlarmPage } from "./AlarmPage";

const alarm: AlarmRow = {
  id:"11111111-1111-4111-8111-111111111111", device_id:"22222222-2222-4222-8222-222222222222",
  alarm_type:"DEVICE_AVAILABILITY_OFFLINE", correlation_key:"device:222:availability:offline", severity:"MAJOR", state:"ACTIVE",
  summary:"edge-ap-01 is offline.", first_raised_at:"2030-01-01T00:00:00Z", last_raised_at:"2030-01-01T00:00:00Z", last_cleared_at:null,
  acknowledged_at:null, acknowledged_by_user_id:null, owner_user_id:null, occurrence_count:1, last_event_id:null,
  created_at:"2030-01-01T00:00:00Z", updated_at:"2030-01-01T00:00:00Z", device_display_name:"edge-ap-01", availability_status:"OFFLINE",
  management_ip:"192.0.2.10", owner_display_name:null, acknowledged_by_display_name:null,
};

afterEach(() => vi.unstubAllGlobals());

describe("AlarmPage", () => {
  it("renders the scoped alarm queue and exposes permitted workflow actions", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      let body: unknown;
      if (url.includes("/alarms/summary")) body = {active_total:1,unacknowledged:1,info:0,warning:0,minor:0,major:1,critical:0};
      else if (url.includes("/alarms/page")) body = {items:[alarm],total:1,page:1,page_size:50};
      else if (url.includes("/history")) body = [{id:"h1",alarm_id:alarm.id,event_id:null,occurred_at:alarm.created_at,action:"OPENED",actor_user_id:null,actor_display_name:null,note:null,before_summary:null,after_summary:{state:"ACTIVE"},metadata:{}}];
      else if (url.includes("/events")) body = [{id:"e1",device_id:alarm.device_id,event_type:"DEVICE_AVAILABILITY_OFFLINE",severity:"MAJOR",correlation_key:alarm.correlation_key,occurred_at:alarm.created_at,summary:alarm.summary,metadata:{}}];
      else if (url.endsWith("/acknowledge") && init?.method === "POST") body = {...alarm, acknowledged_at:"2030-01-01T00:01:00Z"};
      else body = alarm;
      return new Response(JSON.stringify(body), {status:200, headers:{"Content-Type":"application/json"}});
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<DialogProvider><FeedbackProvider><AlarmPage token="test-token" currentUserId="33333333-3333-4333-8333-333333333333" permissions={["alarm.read","alarm.acknowledge","alarm.assign","alarm.clear"]} /></FeedbackProvider></DialogProvider>);

    expect(await screen.findByText("edge-ap-01")).toBeInTheDocument();
    fireEvent.click(screen.getByText("edge-ap-01"));
    expect(await screen.findByRole("button", {name:"Acknowledge"})).toBeInTheDocument();
    expect(screen.getByRole("button", {name:"Assign to me"})).toBeInTheDocument();
    expect(screen.getByRole("button", {name:"Clear alarm"})).toBeInTheDocument();
    expect(await screen.findByText("Device Availability Offline")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", {name:"Acknowledge"}));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith(`/alarms/${alarm.id}/acknowledge`) && (init as RequestInit)?.method === "POST")).toBe(true));
  });
});
