import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DialogProvider } from "../components/common/DialogSystem";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import { MaintenancePage } from "./MaintenancePage";
import type { MaintenanceWindow } from "../types";


afterEach(() => vi.unstubAllGlobals());

function json(body:unknown,status=200){return new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json"}})}

const upcoming={
  id:"mw-1",name:"Planned upgrade",reason:"Original",target_type:"LOCATION" as const,target_id:"loc-1",target_display_name:"Central Site",
  starts_at:"2030-01-01T12:00:00Z",ends_at:"2030-01-01T13:00:00Z",enabled:true,cancelled_at:null,created_by_user_id:"u-1",cancelled_by_user_id:null,
  state:"UPCOMING" as const,created_at:"2029-12-01T00:00:00Z",updated_at:"2029-12-01T00:00:00Z",
};

function renderMaintenance(row:MaintenanceWindow={...upcoming}, calls:Array<{url:string;method:string;body:string}>=[]){
  vi.stubGlobal("fetch",vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
    const url=String(input);const method=init?.method||"GET";calls.push({url,method,body:String(init?.body||"")});
    if(url.includes("/maintenance-windows?")&&method==="GET")return json({items:[row],total:1,page:1,page_size:25});
    if(url.includes("/maintenance-windows/targets"))return json({items:[],total:0,page:1,page_size:50});
    if(url.endsWith(`/maintenance-windows/${row.id}`)&&method==="PUT")return json({...row,name:"Updated maintenance"});
    if(url.includes("/cancel"))return json({...row,state:"CANCELLED",cancelled_at:"2030-01-01T11:00:00Z"});
    return json({});
  }));
  return render(<DialogProvider><FeedbackProvider><MaintenancePage token="test-token" permissions={["maintenance.read","maintenance.manage"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);
}

describe("ENH-6 upcoming maintenance editing",()=>{
  it("opens the existing maintenance form in edit mode and saves through the manage-protected PUT route",async()=>{
    const calls:Array<{url:string;method:string;body:string}>=[];
    renderMaintenance({...upcoming},calls);
    expect(await screen.findByText("Planned upgrade")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button",{name:"Edit"}));
    const heading=screen.getByRole("heading",{name:"Edit upcoming maintenance"});
    expect(heading).toHaveAttribute("data-help",expect.stringContaining("Only upcoming maintenance windows can be edited"));
    fireEvent.change(screen.getByLabelText("Name"),{target:{value:"Updated maintenance"}});
    fireEvent.click(screen.getByRole("button",{name:"Save changes"}));
    await waitFor(()=>expect(calls.some(call=>call.url.endsWith("/maintenance-windows/mw-1")&&call.method==="PUT"&&JSON.parse(call.body).name==="Updated maintenance")).toBe(true));
  });

  it("does not expose Edit after maintenance has started",async()=>{
    renderMaintenance({...upcoming,id:"mw-active",state:"ACTIVE" as const,starts_at:"2029-12-31T12:00:00Z"});
    expect(await screen.findByText("Planned upgrade")).toBeInTheDocument();
    expect(screen.queryByRole("button",{name:"Edit"})).not.toBeInTheDocument();
    expect(screen.getByRole("button",{name:"Cancel"})).toBeInTheDocument();
  });
});
