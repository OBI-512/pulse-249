import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import { DialogProvider } from "../components/common/DialogSystem";
import { DataReportingPage } from "./DataReportingPage";

afterEach(() => vi.unstubAllGlobals());

function json(body: unknown) {
  return new Response(JSON.stringify(body), {status: 200, headers: {"Content-Type": "application/json"}});
}

describe("DataReportingPage Phase-D UAT regressions", () => {
  it("uses the application sortable-table pattern across all four workspaces", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/telemetry/summary")) return json({total:1,enabled:1,due:0,ok:1,error:0,pending:0,disabled:0,oldest_due_at:null});
      if (url.includes("/telemetry/profiles")) return json([{id:"p1",device_type_id:"t1",device_type_code:"OTHER",device_type_name:"Other",name:"Other",enabled:true,protocol:"SNMP",interval_seconds:900,timeout_seconds:5,retries:1,max_metrics:32,metric_definitions:[],vendor_extensions:{},description:null}]);
      if (url.includes("/telemetry/states")) return json({items:[{id:"s1",device_id:"d1",device_display_name:"Device 1",profile_id:"p1",enabled:true,status:"OK",last_collect_at:null,last_success_at:null,last_failure_at:null,next_collect_at:null,consecutive_failures:0,last_error_code:null,last_duration_ms:null}],total:1,page:1,page_size:50});
      if (url.includes("/data-lifecycle/policies")) return json([{id:"r1",data_class:"TELEMETRY_RAW",enabled:true,retain_days:30,rollup_after_days:7,batch_hours:24,description:null}]);
      if (url.includes("/data-lifecycle/capacity")) return json({generated_at:"2030-01-01T00:00:00Z",estimates:[]});
      if (url.includes("/data-lifecycle/runs")) return json({items:[{id:"l1",data_class:"TELEMETRY_RAW",status:"COMPLETED",started_at:"2030-01-01T00:00:00Z",completed_at:"2030-01-01T00:01:00Z",scanned_rows:1,rolled_up_rows:1,purged_rows:0,error_code:null}],total:1,page:1,page_size:50});
      if (url.includes("/data-exchange/imports")) return json({items:[],total:0,page:1,page_size:50});
      if (url.includes("/reports/catalog")) return json([{code:"inventory",name:"Inventory",description:"Inventory",sensitive_fields:[],supported_formats:["CSV"],filters:[]}]);
      if (url.includes("/reports/definitions?state=deleted")) return json([]);
      if (url.includes("/reports/definitions")) return json([]);
      if (url.includes("/reports/jobs")) return json({items:[],total:0,page:1,page_size:50});
      if (url.includes("/reports/schedules?state=deleted")) return json([]);
      if (url.includes("/reports/schedules")) return json([]);
      if (url.includes("/reports/deliveries")) return json({items:[],total:0,page:1,page_size:50});
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);

    const permissions = [
      "telemetry.read", "telemetry.manage", "data_lifecycle.read", "data_lifecycle.manage",
      "data_exchange.read", "data_exchange.import", "data_exchange.export", "report.read",
      "report.manage", "report.export", "report.schedule", "report.sensitive",
    ];

    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={permissions} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    expect(await screen.findByRole("button", {name:"Device type: ascending"})).toBeInTheDocument();
    expect(screen.getByRole("button", {name:"Next due: ascending"})).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Data Lifecycle"}));
    const retentionSection = (await screen.findByRole("heading", {name:"Retention policies"})).closest("section");
    const lifecycleRunsSection = screen.getByRole("heading", {name:"Lifecycle execution evidence"}).closest("section");
    expect(retentionSection).not.toBeNull();
    expect(lifecycleRunsSection).not.toBeNull();
    expect(within(retentionSection as HTMLElement).getByRole("button", {name:"Data class: ascending"})).toBeInTheDocument();
    expect(within(lifecycleRunsSection as HTMLElement).getByRole("button", {name:"Started: descending"})).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Import / Export"}));
    const importHistorySection = (await screen.findByRole("heading", {name:"Your import history"})).closest("section");
    expect(importHistorySection).not.toBeNull();
    expect(within(importHistorySection as HTMLElement).getByRole("button", {name:"Created: descending"})).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Reports"}));
    const reportJobsSection = (await screen.findByRole("heading", {name:"Report jobs"})).closest("section");
    expect(reportJobsSection).not.toBeNull();
    expect(within(reportJobsSection as HTMLElement).getByRole("button", {name:"Requested: descending"})).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", {name:"Scheduled Reports"}));
    const configurationSection = screen.getByRole("heading", {name:"Configuration management"}).closest("section");
    expect(configurationSection).not.toBeNull();
    expect(within(configurationSection as HTMLElement).getByRole("button", {name:"Name: ascending"})).toBeInTheDocument();
    expect(within(configurationSection as HTMLElement).getByRole("button", {name:"Enabled: not sorted"})).toBeInTheDocument();

    fireEvent.click(within(reportJobsSection as HTMLElement).getByRole("button", {name:"Name: not sorted"}));
    await waitFor(() => {
      const currentReportJobsSection = screen.getByRole("heading", {name:"Report jobs"}).closest("section");
      expect(currentReportJobsSection).not.toBeNull();
      expect(within(currentReportJobsSection as HTMLElement).getByRole("button", {name:"Name: ascending"})).toBeInTheDocument();
    });
  });

  it("keeps report filters user-friendly while sending structured filters internally", async () => {
    let runBody: any = null;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/reports/catalog")) return json([{
        code:"inventory", name:"Inventory", description:"Inventory", sensitive_fields:[], supported_formats:["CSV"],
        filters:["device_type","lifecycle_state","operational_state"],
      }]);
      if (url.includes("/reports/definitions?state=deleted")) return json([]);
      if (url.includes("/reports/definitions")) return json([]);
      if (url.includes("/reports/jobs") && (!init?.method || init.method === "GET")) return json({items:[],total:0,page:1,page_size:50});
      if (url.endsWith("/reports/run")) { runBody = JSON.parse(String(init?.body || "{}")); return json({id:"j1",report_type:"inventory",format:"CSV",status:"QUEUED",filters:runBody.filters,include_sensitive:false,requested_at:"2030-01-01T00:00:00Z",completed_at:null,row_count:0,artifact_name:null,artifact_size:null,error_code:null,error_message:null}); }
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["report.read","report.export"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    expect(await screen.findByLabelText("Device type")).toBeInTheDocument();
    expect(screen.queryByText("Filters JSON")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Device type"), {target:{value:"ROUTER"}});
    fireEvent.change(screen.getByLabelText("Lifecycle state"), {target:{value:"ACTIVE"}});
    fireEvent.click(screen.getByRole("button", {name:"Run report"}));

    await waitFor(() => expect(runBody).not.toBeNull());
    expect(runBody.filters).toEqual({device_type:"ROUTER", lifecycle_state:"ACTIVE"});
    expect(JSON.stringify(runBody)).toContain('"filters"');
  });

});

describe("DataReportingPage pagination coverage", () => {
  it("enables the standard pagination pattern for every Data & Reports table", async () => {
    const profiles = Array.from({length:51}, (_,i) => ({id:`p${i}`,device_type_id:`t${i}`,device_type_code:`TYPE_${i}`,device_type_name:`Type ${i}`,name:`Type ${i}`,enabled:true,protocol:"SNMP",interval_seconds:900,timeout_seconds:5,retries:1,max_metrics:32,metric_definitions:[],vendor_extensions:{},description:null}));
    const policies = Array.from({length:51}, (_,i) => ({id:`r${i}`,data_class:`CLASS_${i}`,enabled:true,retain_days:30,rollup_after_days:7,batch_hours:24,description:null}));
    const schedules = Array.from({length:51}, (_,i) => ({id:`sc${i}`,name:`Schedule ${i}`,report_type:"inventory",format:"CSV",interval_minutes:1440,enabled:true,next_run_at:"2030-01-01T00:00:00Z",last_run_at:null,channel_type:null,destination:null}));
    const definitions = Array.from({length:51}, (_,i) => ({id:`def${i}`,name:`Definition ${i}`,report_type:"inventory",format:"CSV",filters:{},include_sensitive:false,description:null,deleted_at:null,purge_after:null,linked_schedules:[]}));
    const importJob = {id:"job-1",entity_type:"devices",file_format:"CSV",filename:"devices.csv",file_sha256:"abc",status:"PREVIEWED",total_records:51,imported_records:0,error_records:0,preview_expires_at:null,committed_at:null,validation_summary:{},created_at:"2030-01-01T00:00:00Z"};
    const previewRecords = Array.from({length:51}, (_,i) => ({id:`ir${i}`,row_number:i+1,status:"VALID",error_code:null,error_message:null,source_data:{name:`Device ${i}`},normalized_data:{}}));

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/telemetry/summary")) return json({total:51,enabled:51,due:0,ok:51,error:0,pending:0,disabled:0,oldest_due_at:null});
      if (url.includes("/telemetry/profiles")) return json(profiles);
      if (url.includes("/telemetry/states")) return json({items:[{id:"s1",device_id:"d1",device_display_name:"Device 1",profile_id:"p1",enabled:true,status:"OK",last_collect_at:null,last_success_at:null,last_failure_at:null,next_collect_at:null,consecutive_failures:0,last_error_code:null,last_duration_ms:null}],total:51,page:1,page_size:50});
      if (url.includes("/data-lifecycle/policies")) return json(policies);
      if (url.includes("/data-lifecycle/capacity")) return json({generated_at:"2030-01-01T00:00:00Z",estimates:[]});
      if (url.includes("/data-lifecycle/runs")) return json({items:[],total:51,page:1,page_size:50});
      if (url.includes("/data-exchange/imports/job-1")) return json({job:importJob,records:previewRecords});
      if (url.includes("/data-exchange/imports")) return json({items:[importJob],total:51,page:1,page_size:50});
      if (url.includes("/reports/catalog")) return json([{code:"inventory",name:"Inventory",description:"Inventory",sensitive_fields:[],supported_formats:["CSV"],filters:[]}]);
      if (url.includes("/reports/definitions?state=deleted")) return json([]);
      if (url.includes("/reports/definitions")) return json({items:definitions.slice(0,50),total:51,page:1,page_size:50});
      if (url.includes("/reports/jobs")) return json({items:[],total:51,page:1,page_size:50});
      if (url.includes("/reports/schedules?state=deleted")) return json([]);
      if (url.includes("/reports/schedules")) return json({items:schedules.slice(0,50),total:51,page:1,page_size:50});
      if (url.includes("/reports/deliveries")) return json({items:[],total:51,page:1,page_size:50});
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);

    const permissions = [
      "telemetry.read", "telemetry.manage", "data_lifecycle.read", "data_lifecycle.manage",
      "data_exchange.read", "data_exchange.import", "data_exchange.export", "report.read",
      "report.manage", "report.export", "report.schedule", "report.sensitive",
    ];
    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={permissions} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    expect(await screen.findByLabelText("telemetry profiles pagination")).toBeInTheDocument();
    expect(screen.getByLabelText("telemetry states pagination")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Data Lifecycle"}));
    expect(await screen.findByLabelText("retention policies pagination")).toBeInTheDocument();
    expect(screen.getByLabelText("lifecycle runs pagination")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Import / Export"}));
    expect(await screen.findByLabelText("import jobs pagination")).toBeInTheDocument();
    fireEvent.doubleClick(screen.getByText("devices.csv"));
    expect(await screen.findByLabelText("import preview rows pagination")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", {name:"Reports"}));
    expect(await screen.findByLabelText("report jobs pagination")).toBeInTheDocument();
    expect(screen.getByLabelText("saved definitions pagination")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", {name:"Scheduled Reports"}));
    expect(await screen.findByLabelText("scheduled reports pagination")).toBeInTheDocument();
    expect(screen.getByLabelText("report deliveries pagination")).toBeInTheDocument();
  });
});

describe("DataReportingPage granular selectors", () => {
  it("uses searchable independent scope selectors and backfills ancestors from a sector", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url=String(input);
      if(url.includes("/data-exchange/imports")) return json({items:[],total:0,page:1,page_size:50});
      if(url.includes("/networks/page")) return json({items:[{id:"n1",name:"Network One",code:"N1"}],total:1,page:1,page_size:50});
      if(url.includes("/cities/page")) return json({items:[{id:"c1",name:"City One",code:"C1",network_id:"n1",network_name:"Network One"}],total:1,page:1,page_size:50});
      if(url.includes("/locations/page")) return json({items:[{id:"l1",name:"Location One",code:"L1",city_id:"c1",city_name:"City One",network_id:"n1",network_name:"Network One"}],total:1,page:1,page_size:50});
      if(url.includes("/sectors/page")) return json({items:[{id:"s1",name:"Sector One",code:"S1",location_id:"l1",location_name:"Location One",city_id:"c1",city_name:"City One",network_id:"n1",network_name:"Network One"}],total:1,page:1,page_size:50});
      if(url.includes("/device-groups/page")) return json({items:[{id:"g1",name:"Group One",code:"G1"}],total:1,page:1,page_size:50});
      return json([]);
    });
    vi.stubGlobal("fetch",fetchMock);
    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["data_exchange.read","data_exchange.import","data_exchange.export","geo.read","geo.create","group.read"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);
    const type=await screen.findByLabelText("Data type");
    fireEvent.change(type,{target:{value:"geography"}});
    const subtype=screen.getByLabelText("Subtype");
    fireEvent.change(subtype,{target:{value:"SECTOR"}});
    expect(subtype).toHaveValue("SECTOR");
    expect(screen.getByLabelText("Network")).toBeEnabled();
    expect(screen.getByLabelText("City")).toBeEnabled();
    expect(screen.getByLabelText("Location")).toBeEnabled();
    const sector=screen.getByLabelText("Sector");
    expect(sector).toBeEnabled();
    fireEvent.focus(sector);
    fireEvent.click(await screen.findByRole("option",{name:/Sector One/}));
    expect(screen.getByLabelText("Sector")).toHaveValue("Sector One");
    expect(screen.getByLabelText("Location")).toHaveValue("Location One");
    expect(screen.getByLabelText("City")).toHaveValue("City One");
    expect(screen.getByLabelText("Network")).toHaveValue("Network One");
    expect(screen.getByRole("button",{name:"Download import template"})).toBeInTheDocument();
    expect(screen.getByRole("button",{name:"Export selected data"})).toBeInTheDocument();
  });


  it("uses group basis and sends VLAN scope filters without exposing raw JSON", async () => {
    let runBody:any=null;
    const fetchMock=vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
      const url=String(input);
      if(url.includes("/device-groups/page")) return json({items:[{id:"g1",name:"VIP CPEs",code:"VIP-CPE"}],total:1,page:1,page_size:50});
      if(url.includes("/cities/page") && url.includes("service_vlan_only=true")) return json({items:[{id:"c1",name:"City One",code:"C1",network_id:"n1",network_name:"Network One",service_vlan_id:222}],total:1,page:1,page_size:50});
      if(url.includes("/devices/management/vlan-options") && url.includes("kind=customer")) return json({items:[{id:"333",label:"333"}],total:1,page:1,page_size:50});
      if(url.includes("/reports/catalog")) return json([{code:"inventory",name:"Inventory",description:"Inventory",sensitive_fields:[],supported_formats:["CSV"],filters:[]}]);
      if(url.includes("/reports/definitions")) return json([]);
      if(url.includes("/reports/jobs")&&(!init?.method||init.method==="GET")) return json({items:[],total:0,page:1,page_size:50});
      if(url.endsWith("/reports/run")){runBody=JSON.parse(String(init?.body||"{}"));return json({id:"j1",report_type:"inventory",format:"CSV",status:"QUEUED",filters:runBody.filters,include_sensitive:false,requested_at:"2030-01-01T00:00:00Z",completed_at:null,row_count:0,artifact_name:null,artifact_size:null,error_code:null,error_message:null});}
      return json({items:[],total:0,page:1,page_size:50});
    });
    vi.stubGlobal("fetch",fetchMock);
    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["report.read","report.export","geo.read","group.read"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    fireEvent.change(await screen.findByLabelText("Scope basis"),{target:{value:"GROUP"}});
    const group=screen.getByLabelText("Group");
    fireEvent.focus(group);
    fireEvent.click(await screen.findByRole("option",{name:/VIP CPEs/}));

    const svlan=screen.getByLabelText("S-VLAN");
    fireEvent.focus(svlan);
    fireEvent.click(await screen.findByRole("option",{name:/222/}));
    const cvlan=screen.getByLabelText("C-VLAN");
    fireEvent.focus(cvlan);
    fireEvent.click(await screen.findByRole("option",{name:/333/}));
    fireEvent.click(screen.getByRole("button",{name:"Run report"}));

    await waitFor(()=>expect(runBody).not.toBeNull());
    expect(runBody.filters).toMatchObject({group_id:"g1",network_id:"n1",city_id:"c1",service_vlan_id:"222",customer_vlan_id:"333"});
    expect(screen.queryByText("Filters JSON")).not.toBeInTheDocument();
  });

  it("sends report geographic scope as an internal structured filter", async () => {
    let runBody:any=null;
    const fetchMock=vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
      const url=String(input);
      if(url.includes("/networks/page")) return json({items:[{id:"n1",name:"Network One",code:"N1"}],total:1,page:1,page_size:50});
      if(url.includes("/reports/catalog")) return json([{code:"inventory",name:"Inventory",description:"Inventory",sensitive_fields:[],supported_formats:["CSV"],filters:[]}]);
      if(url.includes("/reports/definitions")) return json([]);
      if(url.includes("/reports/jobs")&&(!init?.method||init.method==="GET")) return json({items:[],total:0,page:1,page_size:50});
      if(url.endsWith("/reports/run")){runBody=JSON.parse(String(init?.body||"{}"));return json({id:"j1",report_type:"inventory",format:"CSV",status:"QUEUED",filters:runBody.filters,include_sensitive:false,requested_at:"2030-01-01T00:00:00Z",completed_at:null,row_count:0,artifact_name:null,artifact_size:null,error_code:null,error_message:null});}
      return json([]);
    });
    vi.stubGlobal("fetch",fetchMock);
    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["report.read","report.export","geo.read"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);
    const network=await screen.findByLabelText("Network");
    fireEvent.focus(network);
    fireEvent.click(await screen.findByRole("option",{name:/Network One/}));
    fireEvent.click(screen.getByRole("button",{name:"Run report"}));
    await waitFor(()=>expect(runBody).not.toBeNull());
    expect(runBody.filters).toEqual({network_id:"n1"});
    expect(screen.queryByText("Filters JSON")).not.toBeInTheDocument();
  });
});

describe("DataReportingPage telemetry filtering and history ranges", () => {
  it("filters telemetry tables and requests an exact custom history range", async () => {
    const requested:string[]=[];
    const fetchMock=vi.fn(async(input:RequestInfo|URL)=>{
      const url=String(input);requested.push(url);
      if(url.includes("/telemetry/summary")) return json({total:1,enabled:1,due:0,ok:1,error:0,pending:0,disabled:0,oldest_due_at:null});
      if(url.includes("/telemetry/profiles")) return json([
        {id:"p1",device_type_id:"t1",device_type_code:"CPE",device_type_name:"CPE",name:"CPE Standard",enabled:true,protocol:"SNMP",interval_seconds:900,timeout_seconds:5,retries:1,max_metrics:32,metric_definitions:[{key:"sys_uptime_seconds",oid:".1.3.6.1.2.1.1.3.0",kind:"GAUGE",transform:"timeticks_seconds",unit:"seconds"}],vendor_extensions:{},description:null},
        {id:"p2",device_type_id:"t2",device_type_code:"OTHER",device_type_name:"Other",name:"Other Standard",enabled:false,protocol:"SNMP",interval_seconds:900,timeout_seconds:5,retries:1,max_metrics:32,metric_definitions:[],vendor_extensions:{},description:null},
      ]);
      if(url.includes("/telemetry/states")) return json({items:[{id:"s1",device_id:"d1",device_display_name:"UAT-CPE-01",profile_id:"p1",enabled:true,status:"OK",last_collect_at:"2030-01-01T10:00:00Z",last_success_at:"2030-01-01T10:00:00Z",last_failure_at:null,next_collect_at:"2030-01-01T10:15:00Z",consecutive_failures:0,last_error_code:null,last_duration_ms:4.2}],total:1,page:1,page_size:50});
      if(url.includes("/telemetry/devices/d1/metrics/sys_uptime_seconds")) return json({device_id:"d1",metric_key:"sys_uptime_seconds",start:"2030-01-01T08:00:00Z",end:"2030-01-01T10:00:00Z",resolution:"raw",points:[{at:"2030-01-01T10:00:00Z",value:288451,sample_count:1,unit:"seconds",source:"SNMP"}]});
      return json({});
    });
    vi.stubGlobal("fetch",fetchMock);

    render(<DialogProvider><FeedbackProvider><DataReportingPage token="test-token" permissions={["telemetry.read","telemetry.manage"]} refreshKey={0}/></FeedbackProvider></DialogProvider>);

    expect(await screen.findByLabelText("Search telemetry profiles")).toBeInTheDocument();
    const profileSection=screen.getByRole("heading",{name:"Per-device-type profiles"}).closest("section");
    expect(profileSection).not.toBeNull();
    fireEvent.change(screen.getByLabelText("Search telemetry profiles"),{target:{value:"CPE"}});
    expect(within(profileSection as HTMLElement).queryAllByText("CPE").length).toBeGreaterThan(0);
    expect(within(profileSection as HTMLElement).queryAllByText("Other").length).toBe(0);

    fireEvent.change(screen.getByLabelText("Search telemetry devices"),{target:{value:"UAT-CPE-01"}});
    fireEvent.change(screen.getByLabelText("Telemetry device type"),{target:{value:"CPE"}});
    fireEvent.change(screen.getByLabelText("Telemetry state"),{target:{value:"OK"}});
    fireEvent.change(screen.getByLabelText("Telemetry enabled"),{target:{value:"true"}});

    await waitFor(()=>expect(requested.some(url=>{
      if(!url.includes("/telemetry/states?"))return false;
      const parsed=new URL(url,"http://localhost");
      return parsed.searchParams.get("search")==="UAT-CPE-01"&&parsed.searchParams.get("device_type")==="CPE"&&parsed.searchParams.get("status")==="OK"&&parsed.searchParams.get("enabled")==="true";
    })).toBe(true));

    fireEvent.click(screen.getByText("UAT-CPE-01"));
    await waitFor(()=>expect(screen.getByLabelText("Metric")).toHaveValue("sys_uptime_seconds"));
    expect(screen.getByLabelText("Telemetry time range")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Telemetry time range"),{target:{value:"custom"}});
    fireEvent.change(screen.getByLabelText("Telemetry history from"),{target:{value:"2030-01-01T08:00"}});
    fireEvent.change(screen.getByLabelText("Telemetry history to"),{target:{value:"2030-01-01T10:00"}});
    fireEvent.click(screen.getByRole("button",{name:"Load history"}));

    await waitFor(()=>expect(requested.some(url=>{
      if(!url.includes("/telemetry/devices/d1/metrics/sys_uptime_seconds?"))return false;
      const parsed=new URL(url,"http://localhost");
      return parsed.searchParams.get("start")===new Date("2030-01-01T08:00").toISOString()
        && parsed.searchParams.get("end")===new Date("2030-01-01T10:00").toISOString()
        && parsed.searchParams.get("resolution")==="raw"
        && parsed.searchParams.get("limit")==="10000";
    })).toBe(true));
  });
});
