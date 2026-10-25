import { PageLayout } from "../design-system/layouts";
import type { DashboardBreakdown, Network, OperationsDashboard, Page } from "../types";
import { canAccessPage } from "../utils/permissions";
import { Button } from "../design-system/primitives";
import { AvailabilityGauge, AvailabilityStateBar as StateBar, DashboardIcon, DashboardMetricCard as MetricCard, formatDashboardCount as formatCount } from "../design-system/visualizations";

function normalizeType(value: string) {
  return value.trim().toUpperCase().replace(/[\s-]+/g, "_");
}

function deviceTypeBreakdown(rows: DashboardBreakdown[], aliases: string[]): DashboardBreakdown {
  const accepted = new Set(aliases.map(normalizeType));
  return rows.find((row) => accepted.has(normalizeType(row.key)) || accepted.has(normalizeType(row.label))) || {
    key: aliases[0], label: aliases[0], context: null, total: 0, online: 0, suspect: 0, offline: 0, unknown: 0, maintenance: 0,
  };
}

function BreakdownTable({ title, help, rows, empty }: { title: string; help: string; rows: DashboardBreakdown[]; empty: string }) {
  return <section className="panel noc-insight-card noc-breakdown-panel">
    <div className="panel-heading"><div><h3 className="hover-help-title" data-help={help}>{title}</h3></div></div>
    <div className="noc-breakdown-list noc-scroll-list">
      {rows.map(row => <div className="noc-breakdown-row" key={row.key}>
        <div className="noc-breakdown-label"><strong>{row.label}</strong>{row.context && <span>{row.context}</span>}</div>
        <div className="noc-breakdown-state"><StateBar row={row}/><small>{formatCount(row.online)} online {" \u00B7 "}{formatCount(row.offline)} offline {" \u00B7 "}{formatCount(row.suspect)} suspect {" \u00B7 "}{formatCount(row.maintenance)} maintenance</small></div>
        <strong className="noc-breakdown-total">{formatCount(row.total)}</strong>
      </div>)}
      {!rows.length && <div className="empty-cell">{empty}</div>}
    </div>
  </section>;
}

function when(value: string | null | undefined) {
  if (!value) return "\u2014";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function OverviewPage({
  dashboard,
  networks,
  locationTotal,
  discoveryTotal,
  activeDiscovery,
  counts,
  lastUpdated,
  onPage,
  permissions,
}: {
  dashboard: OperationsDashboard | null;
  networks: Network[];
  locationTotal: number;
  discoveryTotal: number;
  activeDiscovery: number;
  counts: Record<string, number>;
  lastUpdated: Date | null;
  onPage: (page: Page) => void;
  permissions: string[];
}) {
  const availability = dashboard?.availability || { total:0, online:0, suspect:0, offline:0, unknown:0, maintenance:0 };
  const alarms = dashboard?.alarms;
  const reachablePercent = availability.total ? Math.round((availability.online / availability.total) * 100) : 0;
  const totalCandidates = Object.values(counts).reduce((sum, value) => sum + value, 0);
  const reviewQueue = (counts.NEW || 0) + (counts.APPROVED || 0);
  const canDevices = canAccessPage("devices", permissions);
  const canAlarms = canAccessPage("alarms", permissions);
  const canDiscovery = canAccessPage("discovery", permissions);
  const canCandidates = canAccessPage("candidates", permissions);
  const canTopology = canAccessPage("topology", permissions);
  const canNetworks = permissions.includes("network.read");
  const canLocations = permissions.includes("geo.read");
  const updatedLabel = lastUpdated ? lastUpdated.toLocaleTimeString([], { hour:"2-digit", minute:"2-digit", second:"2-digit" }) : "initializing";
  const typeRows = dashboard?.by_device_type || [];
  const accessPoints = deviceTypeBreakdown(typeRows, ["ACCESS_POINT", "ACCESS POINT", "AP"]);
  const cpes = deviceTypeBreakdown(typeRows, ["CPE"]);
  const sectors = deviceTypeBreakdown(typeRows, ["SECTOR", "SECTORS"]);
  const authorizedDeviceCategories = new Set(dashboard?.authorized_device_categories || []);
  const showAccessPoints = authorizedDeviceCategories.has("ACCESS_POINT");
  const showCpes = authorizedDeviceCategories.has("CPE");
  const showSectors = authorizedDeviceCategories.has("SECTOR");
  const gaugeCount = 1 + Number(showAccessPoints) + Number(showCpes) + Number(showSectors);

  const openNetworkWorkspace = (tab: "networks" | "locations") => {
    try { window.sessionStorage.setItem("fttw.network-workspace-tab", tab); } catch { /* browser storage is optional */ }
    onPage("networks");
  };

  return <PageLayout className="dashboard-page noc-dashboard">
    <section className="noc-command-hero">
      <div className="noc-command-copy">
        <div className="noc-live-line"><span className="noc-live-dot"/><span>NETWORK OPERATIONS CENTER</span><span>{"\u2022"}</span><span>Server snapshot every 15 seconds</span></div>
        <h2 className="hover-help-title" data-help="Authoritative availability, alarms, outage activity, geography, and network health in one scoped operational view.">Operational Network Dashboard</h2>
        <div className="dashboard-actions noc-command-actions">
          {canAlarms && <Button unstyled className="secondary light" onClick={() => onPage("alarms")}><span className="noc-action-icon"><DashboardIcon name="alarms"/></span><span className="noc-action-label">Alarms queue</span></Button>}
          {canTopology && <Button unstyled className="secondary light" onClick={() => onPage("topology")}><span className="noc-action-icon"><DashboardIcon name="topology"/></span><span className="noc-action-label">Topology</span></Button>}
          {canDevices && <Button unstyled className="secondary light" onClick={() => onPage("devices")}><span className="noc-action-icon"><DashboardIcon name="devices"/></span><span className="noc-action-label">Device inventory</span></Button>}
        </div>
        <small>Last snapshot <strong>{updatedLabel}</strong></small>
      </div>
      <div className={`noc-gauge-cluster noc-gauge-count-${gaugeCount}`} aria-label="Availability gauges">
        {showAccessPoints && <AvailabilityGauge label="Access Points" online={accessPoints.online} total={accessPoints.total}/>}
        {showCpes && <AvailabilityGauge label="CPEs" online={cpes.online} total={cpes.total}/>}
        {showSectors && <AvailabilityGauge label="Sectors" online={sectors.online} total={sectors.total}/>}
        <AvailabilityGauge label="All devices" online={availability.online} total={availability.total} primary/>
      </div>
    </section>

    <section className="noc-metric-grid" aria-label="Authoritative availability metrics">
      <MetricCard icon="devices" label="Managed" value={availability.total} detail="Monitored inventory" tone="blue"/>
      <MetricCard icon="online" label="Online" value={availability.online} detail={`${reachablePercent}% reachable`} tone="green"/>
      <MetricCard icon="offline" label="Offline" value={availability.offline} detail="Confirmed outage" tone="red"/>
      <MetricCard icon="suspect" label="Suspect" value={availability.suspect} detail="Awaiting failure confirmation" tone="amber"/>
      <MetricCard icon="maintenance" label="Maintenance" value={availability.maintenance} detail={`${availability.unknown} unknown`} tone="violet"/>
      {alarms && <MetricCard icon="alarms" label="Active alarms" value={alarms.active_total} detail={`${alarms.unacknowledged} unacknowledged`} tone="alarm"/>}
    </section>

    {alarms && <section className="panel noc-alarm-severity-strip">
      <div><span>Critical</span><strong>{alarms.critical}</strong></div><div><span>Major</span><strong>{alarms.major}</strong></div><div><span>Minor</span><strong>{alarms.minor}</strong></div><div><span>Warning</span><strong>{alarms.warning}</strong></div><div><span>Info</span><strong>{alarms.info}</strong></div>
      {canAlarms && <Button unstyled className="secondary" onClick={() => onPage("alarms")}>Review alarms</Button>}
    </section>}

    <div className="noc-insight-grid">
      <BreakdownTable title="Availability by device type" help="Authoritative availability grouped by device type. Scroll inside this card when more rows are available." rows={dashboard?.by_device_type || []} empty="No device-type data."/>
      <BreakdownTable title="Top locations by managed inventory" help="Locations with the largest managed device populations in your current access scope." rows={dashboard?.top_locations || []} empty="No placed location data."/>
      <BreakdownTable title="Availability by network" help="Authoritative availability grouped by configured network." rows={dashboard?.by_network || []} empty="No placed network data."/>
      <section className="panel noc-insight-card noc-outage-panel">
        <div className="panel-heading"><div><h3 className="hover-help-title" data-help="Newest authoritative OFFLINE events visible in your current scope.">Recent outages</h3></div></div>
        <div className="noc-outage-list noc-scroll-list">
          {dashboard?.recent_outages.map(outage => <div className="noc-outage-row" key={outage.event_id}>
            <span className={`noc-outage-dot status-${(outage.current_status || "unknown").toLowerCase()}`}/>
            <div><strong>{outage.device_display_name}</strong><span>{outage.location_name || "Unplaced"}{outage.network_name ? ` \u00B7 ${outage.network_name}` : ""}</span><small>{when(outage.occurred_at)}</small></div>
            <span className="noc-current-status">{outage.current_status || "UNKNOWN"}</span>
          </div>)}
          {!dashboard?.recent_outages.length && <div className="empty-cell">No recent outages are visible in your scope.</div>}
        </div>
      </section>
    </div>

    <section className="panel noc-workload-panel">
      <div className="panel-heading"><div><h3 className="hover-help-title" data-help="Fast navigation to the operational workspaces that most often need attention during a NOC shift.">Operational workload</h3></div></div>
      <div className="noc-workload-grid">
        {canCandidates && <Button unstyled className="workload-candidates" onClick={() => onPage("candidates")}><span className="noc-workload-icon"><DashboardIcon name="candidates"/></span><span>Candidate review</span><strong>{formatCount(reviewQueue)}</strong><small>{formatCount(totalCandidates)} retained candidates</small></Button>}
        {canDiscovery && <Button unstyled className="workload-discovery" onClick={() => onPage("discovery")}><span className="noc-workload-icon"><DashboardIcon name="discovery"/></span><span>Active discovery</span><strong>{formatCount(activeDiscovery)}</strong><small>{formatCount(discoveryTotal)} retained jobs</small></Button>}
        {canNetworks && <Button unstyled className="workload-networks" onClick={() => openNetworkWorkspace("networks")}><span className="noc-workload-icon"><DashboardIcon name="networks"/></span><span>Configured networks</span><strong>{formatCount(networks.length)}</strong><small>Open network management</small></Button>}
        {canLocations && <Button unstyled className="workload-locations" onClick={() => openNetworkWorkspace("locations")}><span className="noc-workload-icon"><DashboardIcon name="locations"/></span><span>Locations</span><strong>{formatCount(locationTotal)}</strong><small>Open location management</small></Button>}
      </div>
    </section>
  </PageLayout>;
}

