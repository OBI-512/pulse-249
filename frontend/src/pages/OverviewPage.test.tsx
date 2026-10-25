import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { OperationsDashboard } from "../types";
import { OverviewPage } from "./OverviewPage";

const dashboard: OperationsDashboard = {
  generated_at:"2030-01-01T12:00:00Z",
  availability:{total:20000,online:18000,suspect:400,offline:900,unknown:200,maintenance:500},
  alarms:{active_total:42,unacknowledged:11,info:2,warning:7,minor:8,major:20,critical:5},
  authorized_device_categories:["ACCESS_POINT","CPE","SECTOR"],
  by_device_type:[
    {key:"ACCESS_POINT",label:"Access Point",context:null,total:5000,online:4600,suspect:80,offline:250,unknown:20,maintenance:50},
    {key:"CPE",label:"CPE",context:null,total:10000,online:9200,suspect:200,offline:400,unknown:100,maintenance:100},
    {key:"SECTOR",label:"Sector",context:null,total:2500,online:2100,suspect:70,offline:200,unknown:30,maintenance:100},
  ],
  by_network:[{key:"n1",label:"Core Network",context:null,total:20000,online:18000,suspect:400,offline:900,unknown:200,maintenance:500}],
  top_locations:[{key:"l1",label:"Downtown",context:"Core Network",total:3000,online:2700,suspect:50,offline:150,unknown:25,maintenance:75}],
  recent_outages:[{event_id:"e1",device_id:"d1",device_display_name:"edge-ap-01",occurred_at:"2030-01-01T11:55:00Z",summary:"edge-ap-01 is offline.",current_status:"OFFLINE",network_name:"Core Network",location_name:"Downtown"}],
  polling:{enabled:true,status:"HEALTHY",interval_seconds:300,worker_concurrency:8,dispatch_limit_per_tick:100,task_batch_size:25,max_outstanding_devices:500,due_now:7,overdue:0,active_leases:12,checked_last_interval:19950,monitored_devices:20000,latest_check_at:"2030-01-01T12:00:00Z",latest_dispatch_at:"2030-01-01T12:00:00Z",worker_heartbeat_at:"2030-01-01T12:00:00Z",worker_heartbeat_age_seconds:4,redis_status:"ONLINE"},
};

describe("OverviewPage NOC dashboard", () => {
  it("renders the four-gauge NOC command center and operator insight cards", () => {
    render(<OverviewPage
      dashboard={dashboard}
      networks={[]}
      locationTotal={12}
      discoveryTotal={0}
      activeDiscovery={0}
      counts={{NEW:0,APPROVED:0,REJECTED:0,REGISTERED:0}}
      lastUpdated={new Date("2030-01-01T12:00:00Z")}
      onPage={vi.fn()}
      permissions={["device.read","alarm.read","topology.read","candidate.read","discovery.read","network.read","geo.read"]}
    />);

    expect(screen.getByText("Operational Network Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Access Points")).toBeInTheDocument();
    expect(screen.getByText("CPEs")).toBeInTheDocument();
    expect(screen.getByText("Sectors")).toBeInTheDocument();
    expect(screen.getByText("All devices")).toBeInTheDocument();
    expect(screen.getAllByText("18,000").length).toBeGreaterThan(0);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("edge-ap-01")).toBeInTheDocument();
    expect(screen.getByText("Downtown")).toBeInTheDocument();
    expect(screen.getAllByText("Core Network").length).toBeGreaterThan(0);
    expect(screen.getByText("Locations")).toBeInTheDocument();
    expect(screen.queryByText("Polling pipeline")).not.toBeInTheDocument();
  });

  it("renders only backend-authorized device-category gauges and keeps authorized zero visible", () => {
    const scopedDashboard: OperationsDashboard = {
      ...dashboard,
      authorized_device_categories:["ACCESS_POINT"],
      by_device_type:[
        {key:"ACCESS_POINT",label:"Access Point",context:null,total:0,online:0,suspect:0,offline:0,unknown:0,maintenance:0},
      ],
    };
    render(<OverviewPage
      dashboard={scopedDashboard}
      networks={[]}
      locationTotal={0}
      discoveryTotal={0}
      activeDiscovery={0}
      counts={{NEW:0,APPROVED:0,REJECTED:0,REGISTERED:0}}
      lastUpdated={new Date("2030-01-01T12:00:00Z")}
      onPage={vi.fn()}
      permissions={["device.read"]}
    />);

    const gauges = screen.getByLabelText("Availability gauges");
    expect(gauges).toHaveClass("noc-gauge-count-2");
    expect(screen.getByText("Access Points")).toBeInTheDocument();
    expect(within(screen.getByText("Access Points").closest(".noc-gauge") as HTMLElement).getByText("0%")).toBeInTheDocument();
    expect(screen.queryByText("CPEs")).not.toBeInTheDocument();
    expect(screen.queryByText("Sectors")).not.toBeInTheDocument();
    expect(screen.getByText("All devices")).toBeInTheDocument();
  });

  it("reflows CPE plus AP authorization without reserving an unauthorized sector gauge", () => {
    render(<OverviewPage
      dashboard={{...dashboard, authorized_device_categories:["ACCESS_POINT","CPE"]}}
      networks={[]} locationTotal={0} discoveryTotal={0} activeDiscovery={0}
      counts={{NEW:0,APPROVED:0,REJECTED:0,REGISTERED:0}}
      lastUpdated={null} onPage={vi.fn()} permissions={["device.read"]}
    />);
    expect(screen.getByLabelText("Availability gauges")).toHaveClass("noc-gauge-count-3");
    expect(screen.getByText("Access Points")).toBeInTheDocument();
    expect(screen.getByText("CPEs")).toBeInTheDocument();
    expect(screen.queryByText("Sectors")).not.toBeInTheDocument();
    expect(screen.getByText("All devices")).toBeInTheDocument();
  });

});
