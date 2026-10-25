import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DialogProvider } from "../components/common/DialogSystem";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import { DataReportingPage } from "./DataReportingPage";

afterEach(() => vi.unstubAllGlobals());

function json(body: unknown, status=200) {
  return new Response(JSON.stringify(body), {status, headers:{"Content-Type":"application/json"}});
}
const page=(items:unknown[],total=items.length)=>({items,total,page:1,page_size:50});

const definition={id:"def-1",name:"North Inventory",report_type:"inventory",format:"CSV",filters:{},include_sensitive:false,description:"North region inventory",deleted_at:null,purge_after:null,linked_schedules:[{id:"sch-1",name:"Daily North Inventory",deleted_at:null}],created_at:"2030-01-01T00:00:00Z",updated_at:"2030-01-01T00:00:00Z"};
const deletedDefinition={...definition,id:"def-deleted",name:"Old Inventory",deleted_at:"2030-01-03T00:00:00Z",purge_after:"2030-02-02T00:00:00Z",linked_schedules:[{id:"sch-deleted",name:"Old Daily Inventory",deleted_at:"2030-01-03T00:00:00Z"}]};
const job={id:"job-1",definition_id:null,schedule_id:null,report_type:"inventory",display_name:"Inventory — North — 2030-01-01 00:00 UTC",format:"CSV",status:"COMPLETED",filters:{},include_sensitive:false,requested_at:"2030-01-01T00:00:00Z",completed_at:"2030-01-01T00:01:00Z",row_count:12,artifact_name:"inventory-north.csv",artifact_size:128,error_code:null,error_message:null};
const schedule={id:"sch-1",definition_id:"def-1",definition_name:"North Inventory",definition_deleted_at:null,name:"Daily North Inventory",report_type:"inventory",format:"CSV",filters:{},include_sensitive:false,interval_minutes:1440,enabled:true,next_run_at:"2030-01-02T00:00:00Z",last_run_at:null,channel_type:null,destination:null,max_attempts:3,retry_base_seconds:60,deleted_at:null,purge_after:null};
const deletedSchedule={...schedule,id:"sch-deleted",name:"Old Daily Inventory",enabled:false,deleted_at:"2030-01-03T00:00:00Z",purge_after:"2030-02-02T00:00:00Z",definition_deleted_at:"2030-01-03T00:00:00Z"};

function renderReports(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch",fetchMock);
  return render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["report.read","report.manage","report.export","report.schedule"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);
}

function commonFetch(calls?:Array<{url:string;method:string;body:string}>) {
  return vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
    const url=String(input); const method=init?.method||"GET"; calls?.push({url,method,body:String(init?.body||"")});
    if(url.includes("/reports/catalog")) return json([{code:"inventory",name:"Inventory",description:"Inventory",sensitive_fields:[],supported_formats:["CSV"],filters:[]}]);
    if(url.includes("/reports/jobs")&&method==="DELETE") return json({deleted:1,deleted_ids:["job-1"]});
    if(url.includes("/reports/jobs")) return json({items:[job],total:1,page:1,page_size:50});
    if(url.includes("/reports/definitions")) return json(page(url.includes("state=deleted")?[deletedDefinition]:[definition],51));
    if(url.includes("/reports/schedules")) return json(page(url.includes("state=deleted")?[deletedSchedule]:[schedule],51));
    if(url.includes("/reports/deliveries")) return json({items:[],total:0,page:1,page_size:50});
    if(url.endsWith("/reports/run")&&method==="POST") return json({...job,id:"job-2",schedule_id:"sch-1",status:"QUEUED",artifact_name:null});
    if(url.includes("/restore")) return json({});
    if(url.includes("/permanent")) return json({deleted:true,permanent:true});
    if(method==="DELETE") return json({deleted:true,recoverable:true,purge_after:"2030-02-02T00:00:00Z"});
    return json({});
  });
}

describe("ENH-3 report management lifecycle closure", () => {
  it("keeps generated report deletion direct and preserves Run Now semantics", async () => {
    const calls:Array<{url:string;method:string;body:string}>=[];
    renderReports(commonFetch(calls));
    expect(await screen.findByText("Inventory — North — 2030-01-01 00:00 UTC")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab",{name:"Scheduled Reports"}));
    fireEvent.click(await screen.findByRole("button",{name:"Run Now"}));
    await waitFor(()=>expect(calls.some(call=>call.url.endsWith("/reports/run")&&call.method==="POST"&&JSON.parse(call.body).schedule_id==="sch-1")).toBe(true));
    expect(calls.some(call=>call.url.includes("/reports/schedules/sch-1")&&call.method==="PATCH")).toBe(false);
    fireEvent.click(screen.getByTitle("Delete generated report"));
    fireEvent.click(await screen.findByRole("button",{name:"Delete report"}));
    await waitFor(()=>expect(calls.some(call=>call.url.endsWith("/reports/jobs")&&call.method==="DELETE")).toBe(true));
  });

  it("uses integrated close control, dual save actions, and closes stale editors when the item is deleted", async () => {
    const calls:Array<{url:string;method:string;body:string}>=[];
    renderReports(commonFetch(calls));
    await screen.findByText("North Inventory");
    const config=screen.getByRole("heading",{name:"Configuration management"}).closest("section") as HTMLElement;
    fireEvent.click(within(config).getByRole("button",{name:"Edit"}));
    expect(await screen.findByRole("tab",{name:"Edit Saved Definition · North Inventory"})).toBeInTheDocument();
    expect(screen.getByRole("button",{name:"Back to Reports"})).toBeInTheDocument();
    expect(screen.getAllByRole("button",{name:"Save changes"})).toHaveLength(2);
    fireEvent.click(screen.getByRole("button",{name:"Back to Reports"}));
    expect(screen.getByRole("tab",{name:"Edit Saved Definition · North Inventory"})).toBeInTheDocument();
    const configAgain=screen.getByRole("heading",{name:"Configuration management"}).closest("section") as HTMLElement;
    fireEvent.click(within(configAgain).getByRole("button",{name:"Delete"}));
    fireEvent.click(await screen.findByRole("button",{name:"Move to Deleted"}));
    await waitFor(()=>expect(screen.queryByRole("tab",{name:"Edit Saved Definition · North Inventory"})).toBeNull());
  });

  it("paginates and filters configuration management and exposes definition-schedule relationships", async () => {
    const calls:Array<{url:string;method:string;body:string}>=[];
    renderReports(commonFetch(calls));
    expect(await screen.findByText(/Used by 1 scheduled report/)).toBeInTheDocument();
    expect(screen.getByText("Daily North Inventory")).toBeInTheDocument();
    expect(screen.getByLabelText("saved definitions pagination")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("Search configuration name…"),{target:{value:"North"}});
    await waitFor(()=>expect(calls.some(call=>call.url.includes("/reports/definitions?")&&call.url.includes("search=North")&&call.url.includes("page_size=50"))).toBe(true));

    fireEvent.click(screen.getByRole("tab",{name:"Scheduled Reports"}));
    expect(await screen.findByText("North Inventory")).toBeInTheDocument();
    expect(screen.getByText("Active definition")).toBeInTheDocument();
    expect(screen.getByLabelText("scheduled reports pagination")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab",{name:"Deleted Configurations"}));
    expect(await screen.findByText("Old Inventory")).toBeInTheDocument();
    expect(screen.getByText(/Old Daily Inventory \(Deleted\)/)).toBeInTheDocument();
    expect(screen.getByLabelText("deleted saved definitions pagination")).toBeInTheDocument();
  });
});
