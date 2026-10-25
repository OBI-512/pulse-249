import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import { DialogProvider } from "../components/common/DialogSystem";
import { DataReportingPage } from "./DataReportingPage";

afterEach(() => vi.unstubAllGlobals());

function json(body: unknown) {
  return new Response(JSON.stringify(body), {status: 200, headers: {"Content-Type": "application/json"}});
}

describe("Telemetry snapshot and history presentation", () => {
  it("keeps snapshot-only metrics out of charts and presents their latest values", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/telemetry/summary")) return json({total:1,enabled:0,due:0,ok:0,error:0,pending:0,disabled:1,oldest_due_at:null});
      if (url.includes("/telemetry/profiles")) return json([{
        id:"p1",device_type_id:"t1",device_type_code:"CPE",device_type_name:"CPE",name:"CPE Standard",enabled:false,protocol:"SNMP",interval_seconds:900,timeout_seconds:5,retries:1,max_metrics:32,
        metric_definitions:[
          {key:"sys_uptime_seconds",oid:"1.3.6.1.2.1.1.3.0",kind:"COUNTER",transform:"timeticks_seconds",unit:"seconds"},
          {key:"sys_name",oid:"1.3.6.1.2.1.1.5.0",kind:"STATE",transform:"raw"},
          {key:"if_count",oid:"1.3.6.1.2.1.2.1.0",kind:"GAUGE",transform:"int",unit:"interfaces"},
        ],vendor_extensions:{},description:null,
      }]);
      if (url.includes("/telemetry/states")) return json({items:[{
        id:"s1",device_id:"d1",device_display_name:"UAT-CPE-01",profile_id:"p1",enabled:false,status:"DISABLED",
        last_collect_at:"2030-01-01T10:00:00Z",last_success_at:"2030-01-01T10:00:00Z",last_failure_at:null,next_collect_at:null,
        consecutive_failures:0,last_error_code:null,last_duration_ms:4.2,
      }],total:1,page:1,page_size:50});
      if (url.includes("/telemetry/devices/d1/metrics/sys_name")) return json({device_id:"d1",metric_key:"sys_name",start:"2030-01-01T09:50:00Z",end:"2030-01-01T10:10:00Z",resolution:"raw",points:[{at:"2030-01-01T10:00:00Z",value:"NanoStation M2",sample_count:1,unit:null,source:"SNMP"}]});
      if (url.includes("/telemetry/devices/d1/metrics/if_count")) return json({device_id:"d1",metric_key:"if_count",start:"2030-01-01T09:50:00Z",end:"2030-01-01T10:10:00Z",resolution:"raw",points:[{at:"2030-01-01T10:00:00Z",value:7,sample_count:1,unit:"interfaces",source:"SNMP"}]});
      if (url.includes("/telemetry/devices/d1/metrics/sys_uptime_seconds")) return json({device_id:"d1",metric_key:"sys_uptime_seconds",start:"2030-01-01T09:50:00Z",end:"2030-01-01T10:10:00Z",resolution:"raw",points:[{at:"2030-01-01T10:00:00Z",value:288451,sample_count:1,unit:"seconds",source:"SNMP"}]});
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);

    const {container}=render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["telemetry.read","telemetry.manage"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    fireEvent.click(await screen.findByText("UAT-CPE-01"));

    const snapshotSection=(await screen.findByRole("heading",{name:"Latest telemetry snapshot"})).closest("section");
    expect(snapshotSection).not.toBeNull();
    await waitFor(()=>expect(within(snapshotSection as HTMLElement).getByText("NanoStation M2")).toBeInTheDocument());
    expect(within(snapshotSection as HTMLElement).getByText("7 interfaces")).toBeInTheDocument();
    expect(within(snapshotSection as HTMLElement).getByText("3d 8h 7m")).toBeInTheDocument();

    const metric=screen.getByLabelText("Metric") as HTMLSelectElement;
    expect(metric.value).toBe("sys_uptime_seconds");
    expect(within(metric).queryByRole("option",{name:"System name"})).not.toBeInTheDocument();
    expect(within(metric).queryByRole("option",{name:"Interface count"})).not.toBeInTheDocument();
    expect(within(metric).getByRole("option",{name:"Uptime"})).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button",{name:"Load history"}));
    await waitFor(()=>expect(screen.getAllByText(/288,451 seconds/).length).toBeGreaterThan(0));
    expect(container.textContent).not.toMatch(/[\u00C2\u00C3\uFFFD]/);
  });
});
