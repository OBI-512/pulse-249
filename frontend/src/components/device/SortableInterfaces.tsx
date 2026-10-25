import { useMemo, useState } from "react";
import type { DeviceInterface, SortState } from "../../types";

import { nextSort, sortRows } from "../../utils/sorting";

import { DataTable } from "../../design-system/data/DataTable";
import { PaginatedTableRows } from "../../design-system/data/Pagination";
import { SortHeader } from "../../design-system/data/SortHeader";
import { TableExportButton } from "../../design-system/data/TableExport";
import { ClearFiltersButton } from "../../design-system/composites/FilterBar";
import { Button, Input, Select } from "../../design-system/primitives";
export function SortableInterfaces({ token, deviceId, items, onDelete }: { token?: string; deviceId: string; items: DeviceInterface[]; onDelete?: (item: DeviceInterface) => void }) {
  const [sort, setSort] = useState<SortState>({ key: "interface_name", direction: "asc" });
  const [search,setSearch]=useState("");
  const [statusFilter,setStatusFilter]=useState("");
  const rows = useMemo(()=>{
    const query=search.trim().toLowerCase();
    const filtered=items.filter(item=>(!query||`${item.interface_name} ${item.interface_index??""} ${item.mac_address||""}`.toLowerCase().includes(query))&&(!statusFilter||(item.operational_status||"")===statusFilter));
    return sortRows(filtered, sort, (item, key) => item[key as keyof DeviceInterface]);
  },[items,sort,search,statusFilter]);
  const statuses=useMemo(()=>[...new Set(items.map(item=>item.operational_status).filter(Boolean) as string[])].sort(),[items]);
  return <><div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search interfaces..."/><Select unstyled value={statusFilter} onChange={e=>setStatusFilter(e.target.value)}><option value="">All Operational States</option>{statuses.map(value=><option key={value}>{value}</option>)}</Select><ClearFiltersButton disabled={!search&&!statusFilter} onClick={()=>{setSearch("");setStatusFilter("")}}/><TableExportButton token={token} tableId="device_interfaces" filters={{device_id:deviceId,search,status:statusFilter,sort_by:sort.key,sort_direction:sort.direction}} /></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Name" sortKey="interface_name" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="Index" sortKey="interface_index" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="MAC" sortKey="mac_address" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/><SortHeader label="Operational" sortKey="operational_status" sort={sort} onSort={(key)=>setSort(c=>nextSort(c,key))}/>{onDelete&&<th />}</tr></thead><tbody><PaginatedTableRows items={rows} colSpan={onDelete ? 5 : 4} resetKey={`${search}|${statusFilter}`} itemLabel="interfaces" renderRow={(item)=><tr key={item.id}><td>{item.interface_name}</td><td>{item.interface_index??"-"}</td><td className="mono">{item.mac_address||"-"}</td><td>{item.operational_status||"-"}</td>{onDelete&&<td><Button unstyled className="small danger" onClick={()=>onDelete(item)}>Delete</Button></td>}</tr>} /></tbody></DataTable></>;
}
