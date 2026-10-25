import { useMemo, useState } from "react";
import type { DeviceIP, SortState } from "../../types";

import { nextSort, sortRows } from "../../utils/sorting";

import { DataTable } from "../../design-system/data/DataTable";
import { PaginatedTableRows } from "../../design-system/data/Pagination";
import { SortHeader } from "../../design-system/data/SortHeader";
import { TableExportButton } from "../../design-system/data/TableExport";
import { ClearFiltersButton } from "../../design-system/composites/FilterBar";
import { Button, Input, Select } from "../../design-system/primitives";
export function SortableDeviceIPs({ token, deviceId, ips, onUpdate, onDelete }: { token?: string; deviceId: string; ips: DeviceIP[]; onUpdate?: (ip: DeviceIP) => void; onDelete?: (ip: DeviceIP) => void }) {
  const [sort, setSort] = useState<SortState>({ key: "ip_address", direction: "asc" });
  const [search,setSearch]=useState("");
  const [managementFilter,setManagementFilter]=useState("");
  const [primaryFilter,setPrimaryFilter]=useState("");
  const rows = useMemo(()=>{
    const query=search.trim().toLowerCase();
    const filtered=ips.filter(item=>(!query||`${item.ip_address} ${item.source||""}`.toLowerCase().includes(query))&&(!managementFilter||String(item.is_management)===managementFilter)&&(!primaryFilter||String(item.is_primary)===primaryFilter));
    return sortRows(filtered, sort, (item, key) => item[key as keyof DeviceIP]);
  },[ips,sort,search,managementFilter,primaryFilter]);
  const hasActions = Boolean(onUpdate || onDelete);
  return <><div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search IP addresses..."/><Select unstyled value={managementFilter} onChange={e=>setManagementFilter(e.target.value)}><option value="">Management or Other</option><option value="true">Management</option><option value="false">Not Management</option></Select><Select unstyled value={primaryFilter} onChange={e=>setPrimaryFilter(e.target.value)}><option value="">Primary or Secondary</option><option value="true">Primary</option><option value="false">Not Primary</option></Select><ClearFiltersButton disabled={!search&&!managementFilter&&!primaryFilter} onClick={()=>{setSearch("");setManagementFilter("");setPrimaryFilter("")}}/><TableExportButton token={token} tableId="device_ips" filters={{device_id:deviceId,search,management:managementFilter,primary:primaryFilter,sort_by:sort.key,sort_direction:sort.direction}} /></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="IP" sortKey="ip_address" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="Management" sortKey="is_management" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="Primary" sortKey="is_primary" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="Source" sortKey="source" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/>{hasActions&&<th />}</tr></thead><tbody><PaginatedTableRows items={rows} colSpan={hasActions ? 5 : 4} resetKey={`${search}|${managementFilter}|${primaryFilter}`} itemLabel="IP addresses" renderRow={(ip)=><tr key={ip.id}><td className="mono">{ip.ip_address}</td><td>{ip.is_management?"Yes":"No"}</td><td>{ip.is_primary?"Yes":"No"}</td><td>{ip.source||"-"}</td>{hasActions&&<td className="actions">{onUpdate&&<Button unstyled className="small secondary" onClick={()=>onUpdate(ip)}>Toggle flags</Button>}{onDelete&&<Button unstyled className="small danger" onClick={()=>onDelete(ip)}>Delete</Button>}</td>}</tr>} /></tbody></DataTable></>;
}
