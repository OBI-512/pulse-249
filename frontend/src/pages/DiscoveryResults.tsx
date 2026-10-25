import { useMemo, useState } from "react";
import type { DiscoveryResult, SortState } from "../types";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { nextSort, sortRows } from "../utils/sorting";
import { Input, Select } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { PaginatedCollection, PaginatedTableRows } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";

const HOSTNAME_PRIORITY: Record<string, number> = { SNMP: 100, HTTPS: 70, HTTP: 60, TCP: 20, ICMP: 10 };
const IDENTITY_PRIORITY: Record<string, number> = { SNMP: 100, HTTPS: 80, HTTP: 70, TCP: 10, ICMP: 0 };
const METHOD_PRIORITY: Record<string, number> = { SNMP: 100, HTTPS: 90, HTTP: 80, TCP: 60, ICMP: 40 };

function pickField(rows: DiscoveryResult[], field: "hostname" | "vendor" | "model" | "serial_number", priority: Record<string, number>) {
  const candidates = rows
    .filter((item) => item.status === "DISCOVERED" && item[field])
    .map((item) => ({ value: item[field] as string, source: item.discovery_method.toUpperCase(), rank: priority[item.discovery_method.toUpperCase()] ?? 0 }))
    .sort((a, b) => b.rank - a.rank);
  return candidates[0] || null;
}

function summarize(results: DiscoveryResult[]) {
  const groups = new Map<string, DiscoveryResult[]>();
  for (const item of results) {
    groups.set(item.ip_address, [...(groups.get(item.ip_address) || []), item]);
  }
  return [...groups.entries()].map(([ip, rows]) => {
    const hostname = pickField(rows, "hostname", HOSTNAME_PRIORITY);
    const vendor = pickField(rows, "vendor", IDENTITY_PRIORITY);
    const model = pickField(rows, "model", IDENTITY_PRIORITY);
    const serial = pickField(rows, "serial_number", IDENTITY_PRIORITY);
    const successful = rows.filter((item) => item.status === "DISCOVERED");
    const primary = [...successful].sort((a, b) => (METHOD_PRIORITY[b.discovery_method.toUpperCase()] ?? 0) - (METHOD_PRIORITY[a.discovery_method.toUpperCase()] ?? 0))[0];
    const protocols = Object.fromEntries(rows.map((item) => [item.discovery_method.toUpperCase(), item.status]));
    return { ip, reachable: successful.length > 0, hostname, vendor, model, serial, primary: primary?.discovery_method || null, protocols };
  });
}

export function DiscoveryResults({ results, token, jobId }: { results: DiscoveryResult[]; token?: string; jobId?: string }) {
  const [sort, setSort] = useState<SortState>({ key: "ip_address", direction: "asc" });
  const [search, setSearch] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const filteredResults = useMemo(() => {
    const query = search.trim().toLowerCase();
    return results.filter((item) =>
      (!query || `${item.ip_address} ${item.hostname || ""} ${item.vendor || ""} ${item.model || ""} ${item.serial_number || ""}`.toLowerCase().includes(query))
      && (!methodFilter || item.discovery_method.toUpperCase() === methodFilter)
      && (!statusFilter || item.status === statusFilter)
    );
  }, [results, search, methodFilter, statusFilter]);
  const rows = sortRows(filteredResults, sort, (item, key) => item[key as keyof DiscoveryResult]);
  const summaries = useMemo(() => summarize(filteredResults), [filteredResults]);
  const methods = useMemo(() => [...new Set(results.map(item => item.discovery_method.toUpperCase()))].sort(), [results]);
  const statuses = useMemo(() => [...new Set(results.map(item => item.status))].sort(), [results]);

  return <div className="discovery-results-stack">
    <PaginatedCollection items={summaries} itemLabel="discovered devices">{(pageSummaries) => <div className="consolidated-grid">{pageSummaries.map((summary) => <article className="consolidated-card" key={summary.ip}>
        <div className="consolidated-card-head"><div><span className="eyebrow">CONSOLIDATED DEVICE</span><h4>{summary.hostname?.value || summary.ip}</h4><span className="muted">{summary.ip}</span></div><Badge value={summary.reachable ? "DISCOVERED" : "UNREACHABLE"} /></div>
        <div className="consolidated-fields">
          <div><span>Hostname</span><strong>{summary.hostname?.value || "Unknown"}</strong><small>{summary.hostname ? `Source: ${summary.hostname.source}` : "No hostname evidence"}</small></div>
          <div><span>Vendor</span><strong>{summary.vendor?.value || "Unknown"}</strong><small>{summary.vendor ? `Source: ${summary.vendor.source}` : "No vendor evidence"}</small></div>
          <div><span>Model</span><strong>{summary.model?.value || "Unknown"}</strong><small>{summary.model ? `Source: ${summary.model.source}` : "No model evidence"}</small></div>
          <div><span>Primary protocol</span><strong>{summary.primary || "None"}</strong><small>Strongest successful evidence</small></div>
        </div>
        <div className="protocol-evidence-row">{Object.entries(summary.protocols).map(([method, status]) => <span className={`protocol-pill ${status === "DISCOVERED" ? "protocol-ok" : "protocol-fail"}`} key={method}>{method}: {status === "DISCOVERED" ? "UP" : "DOWN"}</span>)}</div>
      </article>)}</div>}</PaginatedCollection>

    <div className="evidence-heading"><div><h4 className="hover-help-title" data-help="Review individual probe results for troubleshooting.">Protocol evidence</h4></div></div>
    <div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={event=>setSearch(event.target.value)} placeholder="Search discovery evidence..."/><Select unstyled value={methodFilter} onChange={event=>setMethodFilter(event.target.value)}><option value="">All Methods</option>{methods.map(method=><option key={method} value={method}>{method}</option>)}</Select><Select unstyled value={statusFilter} onChange={event=>setStatusFilter(event.target.value)}><option value="">All Statuses</option>{statuses.map(status=><option key={status} value={status}>{status}</option>)}</Select><TableExportButton token={token} tableId="discovery_results" filters={{ job_id: jobId || "", search, method: methodFilter, status: statusFilter, sort_by: sort.key, sort_direction: sort.direction }} disabled={!jobId}/><ClearFiltersButton disabled={!search&&!methodFilter&&!statusFilter} onClick={()=>{setSearch("");setMethodFilter("");setStatusFilter("")}}/></div>
    <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="IP" sortKey="ip_address" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Method" sortKey="discovery_method" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Status" sortKey="status" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Vendor" sortKey="vendor" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Model" sortKey="model" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Hostname" sortKey="hostname" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /><SortHeader label="Serial" sortKey="serial_number" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))} /></tr></thead><tbody><PaginatedTableRows items={rows} colSpan={7} resetKey={`${search}|${methodFilter}|${statusFilter}`} itemLabel="protocol observations" renderRow={(item) => <tr key={item.id}><td>{item.ip_address}</td><td>{item.discovery_method}</td><td><Badge value={item.status} /></td><td>{item.vendor || "-"}</td><td>{item.model || "-"}</td><td>{item.hostname || "-"}</td><td>{item.serial_number || "-"}</td></tr>} /></tbody></DataTable>
  </div>;
}
