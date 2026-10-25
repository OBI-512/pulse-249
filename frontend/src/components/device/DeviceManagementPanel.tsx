import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import type { City, DeviceManagementRow, DeviceType, Group, Location, Network, SortState } from "../../types";
import { useDialog } from "../common/DialogSystem";
import { useFeedback } from "../common/FeedbackSystem";
import { friendlyConflict, friendlyErrorNotice } from "../../utils/feedback";
import { EmptyState } from "../../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../../design-system/composites/Status";
import { nextSort } from "../../utils/sorting";
import { LocalSearchableCombobox } from "../../design-system/composites/SearchableSelect";
import { SearchableCombobox, type ComboboxPage } from "../../design-system/composites/SearchableSelect";
import { PhysicalSectorSearchSelect } from "../common/PhysicalSectorSearchSelect";
import { DataTable } from "../../design-system/data/DataTable";
import { ServerPaginationRow } from "../../design-system/data/Pagination";
import { SortHeader } from "../../design-system/data/SortHeader";
import { TableExportButton } from "../../design-system/data/TableExport";
import { ClearFiltersButton } from "../../design-system/composites/FilterBar";
import { Button, Input, Select } from "../../design-system/primitives";
import { TemplateAssignmentBulkDialog } from "./TemplateAssignmentBulkDialog";

type Filters = {
  search:string;
  network_id:string;
  city_id:string;
  location_id:string;
  physical_sector_device_id:string;
  group_id:string;
  device_type_id:string;
  service_vlan_id:string;
  customer_vlan_id:string;
  lifecycle_state:string;
  operational_state:string;
};

async function mapConcurrent<T, R>(items:T[], concurrency:number,worker:(item:T)=>Promise<R>):Promise<R[]> {
  const results=new Array<R>(items.length);let cursor=0;
  const runners=Array.from({length:Math.min(concurrency,items.length)},async()=>{while(true){const index=cursor++;if(index>=items.length)return;results[index]=await worker(items[index])}});
  await Promise.all(runners);return results;
}

type Props={
  token:string;rows:DeviceManagementRow[];filters:Filters;setFilters:(value:Filters)=>void;
  networks:Network[];cities:City[];locations:Location[];groups:Group[];types:DeviceType[];permissions:string[];
  busy:boolean;total:number;page:number;pageSize:number;sort:SortState;setPage:(page:number)=>void;
  setPageSize:(pageSize:number)=>void;setSort:(updater:SortState|((current:SortState)=>SortState))=>void;onReload:()=>Promise<void>;
};

export function DeviceManagementPanel(props:Props){
  const dialog=useDialog();const feedback=useFeedback();
  const [selected,setSelected]=useState<Set<string>>(new Set());
  const [selectedById,setSelectedById]=useState<Map<string,DeviceManagementRow>>(new Map());
  const [working,setWorking]=useState(false);
  const [degradedAction,setDegradedAction]=useState("MARK");
  const [lifecycle,setLifecycle]=useState("ACTIVE");
  const [templateDialogOpen,setTemplateDialogOpen]=useState(false);
  const canUpdate=props.permissions.includes("device.update");
  const canDelete=props.permissions.includes("device.delete");
  const canTemplateAssign=props.permissions.includes("device.read")&&(
    (props.permissions.includes("access_template.read")&&props.permissions.includes("access_template.manage"))||
    (props.permissions.includes("device.configuration.template.read")&&props.permissions.includes("device.configuration.template.manage")&&props.permissions.includes("device.configuration.read"))
  );
  const canBatchActions=canUpdate||canDelete||canTemplateAssign;
  const selectedRows=useMemo(()=>Array.from(selectedById.values()),[selectedById]);
  const allVisibleSelected=props.rows.length>0&&props.rows.every(row=>selected.has(row.id));
  const visibleCities=props.filters.network_id?props.cities.filter(city=>city.network_id===props.filters.network_id):props.cities;
  const visibleLocations=props.filters.city_id?props.locations.filter(location=>location.city_id===props.filters.city_id):props.locations;
  const networkOptions=useMemo(()=>props.networks.map(item=>({id:item.id,label:item.name,description:item.code,data:item})),[props.networks]);
  const cityOptions=useMemo(()=>visibleCities.map(item=>{const network=props.networks.find(candidate=>candidate.id===item.network_id);return{id:item.id,label:item.name,description:network?.name||item.code,data:item}}),[visibleCities,props.networks]);
  const locationOptions=useMemo(()=>visibleLocations.map(item=>{const city=props.cities.find(candidate=>candidate.id===item.city_id);const network=city?props.networks.find(candidate=>candidate.id===city.network_id):undefined;return{id:item.id,label:item.name,description:[city?.name,network?.name].filter(Boolean).join(" / "),data:item}}),[visibleLocations,props.cities,props.networks]);
  const groupOptions=useMemo(()=>props.groups.map(item=>({id:item.id,label:item.name,description:item.code,data:item})),[props.groups]);
  const loadVlanOptions=useCallback((kind:"service"|"customer")=>async(query:string,page:number,pageSize:number):Promise<ComboboxPage>=>{
    const params=new URLSearchParams({kind,page:String(page),page_size:String(pageSize)});if(query)params.set("search",query);
    if(props.filters.search.trim())params.set("management_search",props.filters.search.trim());
    for(const key of ["network_id","city_id","location_id","physical_sector_device_id","group_id","device_type_id","lifecycle_state","operational_state"] as const){const value=props.filters[key];if(value)params.set(key,value)}
    if(kind!=="service"&&props.filters.service_vlan_id)params.set("service_vlan_id",props.filters.service_vlan_id);
    if(kind!=="customer"&&props.filters.customer_vlan_id)params.set("customer_vlan_id",props.filters.customer_vlan_id);
    const result=await apiFetch<{items:Array<{id:string;label:string;description?:string|null}>;total:number;page:number;page_size:number}>(`/devices/management/vlan-options?${params.toString()}`,{},props.token);
    return {...result,items:result.items.map(item=>({id:item.id,label:item.label,description:item.description||undefined}))};
  },[props.token,props.filters]);

  const clearSelection=useCallback(()=>{setSelected(new Set());setSelectedById(new Map())},[]);
  useEffect(()=>{clearSelection()},[
    clearSelection,props.sort.key,props.sort.direction,props.filters.search,props.filters.network_id,props.filters.city_id,
    props.filters.location_id,props.filters.physical_sector_device_id,props.filters.group_id,props.filters.device_type_id,
    props.filters.service_vlan_id,props.filters.customer_vlan_id,props.filters.lifecycle_state,props.filters.operational_state,
  ]);
  const patchFilters=(patch:Partial<Filters>)=>props.setFilters({...props.filters,...patch});
  const toggle=(id:string)=>{
    const row=props.rows.find(item=>item.id===id);
    setSelected(current=>{const next=new Set(current);if(next.has(id))next.delete(id);else next.add(id);return next});
    setSelectedById(current=>{const next=new Map(current);if(next.has(id))next.delete(id);else if(row)next.set(id,row);return next});
  };
  const toggleAll=()=>{
    setSelected(current=>{const next=new Set(current);if(allVisibleSelected)props.rows.forEach(row=>next.delete(row.id));else props.rows.forEach(row=>next.add(row.id));return next});
    setSelectedById(current=>{const next=new Map(current);if(allVisibleSelected)props.rows.forEach(row=>next.delete(row.id));else props.rows.forEach(row=>next.set(row.id,row));return next});
  };

  const runMany=async(label:string,work:(row:DeviceManagementRow)=>Promise<unknown>)=>{
    if(!selectedRows.length){feedback.error("Select one or more devices from the table before running this action.","No devices selected");return}
    setWorking(true);
    const outcomes=await mapConcurrent(selectedRows,8,async row=>{try{await work(row);return{row,ok:true as const}}catch(error){return{row,ok:false as const,error}}});
    const failures=outcomes.filter((item):item is {row:DeviceManagementRow;ok:false;error:unknown}=>!item.ok);const succeeded=outcomes.length-failures.length;
    await props.onReload();setWorking(false);
    if(failures.length){const first=failures[0];const notice=friendlyErrorNotice(first.error,`${label} could not be completed for every selected device.`,{action:label,entityType:"device",entityName:first.row.display_name});feedback.error(`${succeeded} device(s) were updated successfully and ${failures.length} failed. ${first.row.display_name}: ${notice.message}`,`${label} partially completed`)}
    else{feedback.success(`${succeeded} selected device(s) were updated successfully.`,`${label} complete`);clearSelection()}
  };

  const updateDegradedOverride=async()=>{
    if(!selectedRows.length){feedback.error("Select one or more devices before changing the manual degraded override.","No devices selected");return}
    const decommissioned=selectedRows.filter(row=>row.lifecycle_state==="DECOMMISSIONED");
    if(decommissioned.length){const sample=decommissioned.slice(0,3).map(row=>row.display_name).join(", ");feedback.error(`Manual degradation cannot be changed for ${decommissioned.length} decommissioned selected device(s): ${sample}${decommissioned.length>3?", …":""}. Remove them from the selection and try again.`,"Degraded override unavailable");return}
    const enabled=degradedAction==="MARK";
    if(!await dialog.confirm({title:enabled?"Mark devices degraded":"Clear degraded override",message:`${enabled?"Mark":"Clear the manual degraded override for"} ${selectedRows.length} selected device(s)? UP/DOWN/UNKNOWN remain availability-driven.`,confirmLabel:enabled?"Mark degraded":"Clear override"}))return;
    await runMany("Degraded override",row=>apiFetch(`/devices/${row.id}/status`,{method:"PATCH",body:JSON.stringify({manual_degraded_override:enabled})},props.token));
  };

  const applyLifecycle=async()=>{
    if(!selectedRows.length){feedback.error("Select one or more devices before updating lifecycle.","No devices selected");return}
    const target=lifecycle;const needingChange=selectedRows.filter(row=>row.lifecycle_state!==target);
    if(!needingChange.length){feedback.success(`All ${selectedRows.length} selected device(s) are already ${target}.`,"No lifecycle change needed");return}
    if(target==="MAINTENANCE"){const decommissioned=selectedRows.filter(row=>row.lifecycle_state==="DECOMMISSIONED");if(decommissioned.length){const sample=decommissioned.slice(0,3).map(row=>row.display_name).join(", ");feedback.error(`${decommissioned.length} selected decommissioned device(s) cannot move directly to MAINTENANCE: ${sample}${decommissioned.length>3?", …":""}. Reactivate them to ACTIVE first, then place them into maintenance.`,"Lifecycle update unavailable");return}}
    const isDecommission=target==="DECOMMISSIONED";const reactivationCount=target==="ACTIVE"?selectedRows.filter(row=>row.lifecycle_state==="DECOMMISSIONED").length:0;
    const message=isDecommission?`Move ${needingChange.length} selected device(s) to DECOMMISSIONED? Their operational state will become UNKNOWN.`:reactivationCount?`Set the selected devices to ${target}? ${reactivationCount} decommissioned device(s) will be reactivated after hierarchy validation.`:`Set ${needingChange.length} selected device(s) to ${target}?`;
    if(!await dialog.confirm({title:`Set lifecycle to ${target}`,message,confirmLabel:isDecommission?"Decommission selected":"Apply lifecycle",tone:isDecommission?"danger":"default"}))return;
    await runMany("Lifecycle update",row=>{if(row.lifecycle_state===target)return Promise.resolve(row);if(target==="DECOMMISSIONED")return apiFetch(`/devices/${row.id}/decommission`,{method:"POST"},props.token);if(target==="ACTIVE"&&row.lifecycle_state==="DECOMMISSIONED")return apiFetch(`/devices/${row.id}/reactivate`,{method:"POST"},props.token);return apiFetch(`/devices/${row.id}/status`,{method:"PATCH",body:JSON.stringify({lifecycle_state:target})},props.token)});
  };

  const recycle=async()=>{
    if(!selectedRows.length){feedback.error("Select one or more devices before moving devices to the Recycle Bin.","No devices selected");return}
    setWorking(true);
    try{
      const previews=await mapConcurrent(selectedRows,8,async row=>({row,preview:await apiFetch<any>(`/recycle-bin/preview?entity_type=DEVICE&entity_id=${row.id}`,{},props.token)}));
      const blocked=previews.filter(item=>item.preview.blockers?.length);
      if(blocked.length){const details=blocked.slice(0,4).map(item=>{const reason=friendlyConflict(item.preview.blockers[0]||{},{action:"delete",entityType:item.row.device_type_code,entityName:item.row.display_name});return`${item.row.display_name}: ${reason}`}).join(" ");feedback.error(`${blocked.length} selected device(s) cannot be moved to the Recycle Bin yet. ${details}${blocked.length>4?` ${blocked.length-4} additional blocked device(s) also require attention.`:""}`,"Deletion blocked by dependencies");return}
      const cascadeCustomers=previews.reduce((count,item)=>count+(item.preview.bundled_items||[]).filter((bundle:any)=>bundle.entity_type==="CUSTOMER").length,0);const cascadeServices=previews.reduce((count,item)=>count+(item.preview.bundled_items||[]).filter((bundle:any)=>bundle.entity_type==="CUSTOMER_SERVICE").length,0);
      const cascadeNote=(cascadeCustomers||cascadeServices)?` ${cascadeCustomers} attached customer(s) and ${cascadeServices} customer service(s) will also move to the same recoverable recycle batches.`:"";
      if(!await dialog.confirm({title:"Move selected devices to Recycle Bin",message:`Move ${selectedRows.length} selected device(s) to the Recycle Bin?${cascadeNote} Existing lifecycle and dependency rules will still be enforced.`,confirmLabel:"Move to Recycle Bin",tone:"danger"}))return;
      await runMany("Recycle Bin move",row=>apiFetch(`/devices/${row.id}?confirmed=true`,{method:"DELETE"},props.token));
    }catch(error){const notice=friendlyErrorNotice(error,"The selected devices could not be validated for deletion.",{action:"delete",entityType:"device"});feedback.error(notice.message,"Batch deletion unavailable")}finally{setWorking(false)}
  };

  const clearFilters=()=>props.setFilters({search:"",network_id:"",city_id:"",location_id:"",physical_sector_device_id:"",group_id:"",device_type_id:"",service_vlan_id:"",customer_vlan_id:"",lifecycle_state:"",operational_state:""});

  return <div className="device-management-workspace">
    <section className="panel batch-filter-panel">
      <div className="panel-header management-panel-header"><div><h3 className="hover-help-title" data-help="Filter inventory, select devices, and run safe batch actions.">Device Management</h3></div><Button unstyled className="secondary small" onClick={()=>void props.onReload()} disabled={working||props.busy}>Refresh results</Button></div>
      <div className="management-filter-grid">
        <label>Search<Input unstyled value={props.filters.search} onChange={e=>patchFilters({search:e.target.value})} placeholder="Name, hostname or IP" /></label>
        <label>Network<LocalSearchableCombobox value={props.filters.network_id} options={networkOptions} onChange={option=>patchFilters({network_id:option?.id||"",city_id:"",location_id:"",physical_sector_device_id:"",service_vlan_id:"",customer_vlan_id:""})} placeholder="All networks / search..." emptyText="No networks match this search." /></label>
        <label>City<LocalSearchableCombobox value={props.filters.city_id} options={cityOptions} onChange={option=>patchFilters({city_id:option?.id||"",location_id:"",physical_sector_device_id:"",service_vlan_id:"",customer_vlan_id:""})} placeholder="All cities / search..." emptyText="No cities match this search." /></label>
        <label>Location<LocalSearchableCombobox value={props.filters.location_id} options={locationOptions} onChange={option=>patchFilters({location_id:option?.id||"",physical_sector_device_id:"",customer_vlan_id:""})} placeholder="All locations / search..." emptyText="No locations match this search." /></label>
        <label>Physical sector<PhysicalSectorSearchSelect token={props.token} value={props.filters.physical_sector_device_id} onChange={value=>patchFilters({physical_sector_device_id:value,customer_vlan_id:""})} networkId={props.filters.network_id} cityId={props.filters.city_id} locationId={props.filters.location_id} placeholder="All physical sectors / search..." /></label>
        <label>Group<LocalSearchableCombobox value={props.filters.group_id} options={groupOptions} onChange={option=>patchFilters({group_id:option?.id||"",service_vlan_id:"",customer_vlan_id:""})} placeholder="All groups / search..." emptyText="No groups match this search." /></label>
        <label>Device type<Select unstyled value={props.filters.device_type_id} onChange={e=>patchFilters({device_type_id:e.target.value,customer_vlan_id:""})}><option value="">All types</option>{props.types.map(x=><option key={x.id} value={x.id}>{x.name}</option>)}</Select></label>
        <label>S-VLAN<SearchableCombobox value={props.filters.service_vlan_id} selectedOption={props.filters.service_vlan_id?{id:props.filters.service_vlan_id,label:props.filters.service_vlan_id}:null} onChange={option=>patchFilters({service_vlan_id:option?.id||"",customer_vlan_id:""})} loadPage={loadVlanOptions("service")} placeholder="All S-VLANs / search..." emptyText="No eligible S-VLANs." /></label>
        <label>C-VLAN<SearchableCombobox value={props.filters.customer_vlan_id} selectedOption={props.filters.customer_vlan_id?{id:props.filters.customer_vlan_id,label:props.filters.customer_vlan_id}:null} onChange={option=>patchFilters({customer_vlan_id:option?.id||""})} loadPage={loadVlanOptions("customer")} placeholder="All C-VLANs / search..." emptyText="No eligible C-VLANs." /></label>
        <label>Lifecycle<Select unstyled value={props.filters.lifecycle_state} onChange={e=>patchFilters({lifecycle_state:e.target.value})}><option value="">All lifecycle</option><option>REGISTERED</option><option>ACTIVE</option><option>MAINTENANCE</option><option>DECOMMISSIONED</option></Select></label>
        <label>Operational<Select unstyled value={props.filters.operational_state} onChange={e=>patchFilters({operational_state:e.target.value})}><option value="">All operational</option><option>UP</option><option>DOWN</option><option>DEGRADED</option><option>UNKNOWN</option></Select></label>
      </div>
      <div className="filter-summary management-filter-summary"><div><strong>{props.total}</strong><span>matching devices</span></div><div><strong>{selectedRows.length}</strong><span>selected across pages</span></div><ClearFiltersButton disabled={!Object.values(props.filters).some(Boolean)} onClick={clearFilters}/></div>
    </section>

    {canBatchActions&&<section className="panel management-command-panel">
      <div className="management-command-heading"><div><div className="eyebrow">BATCH ACTIONS</div><h3 className="hover-help-title" data-help="Apply common actions to the devices selected in the table below.">Selected device actions</h3></div></div>
      <div className="management-command-toolbar">
        <div className="management-action-group selection-action-group"><strong className="hover-help-title" data-help="Selection is preserved while paging. Filter or sort changes clear it to avoid hidden stale targets.">Selection</strong><div className="management-action-controls"><Button unstyled className="secondary" onClick={toggleAll}>{allVisibleSelected?"Clear visible":"Select all visible"}</Button><Button unstyled className="secondary" onClick={clearSelection} disabled={!selectedRows.length}>Clear selection</Button></div></div>
        {canTemplateAssign&&<div className="management-action-group template-assignment-action-group"><strong className="hover-help-title" data-help="Preview Access and Configuration Template metadata assignments for the exact selected devices. Assignment never executes configuration.">Templates</strong><div className="management-action-controls"><Button unstyled onClick={()=>setTemplateDialogOpen(true)} disabled={!selectedRows.length||selectedRows.length>500||working}>Assign templates…</Button></div></div>}
        {canUpdate&&<div className="management-action-group status-action-group"><strong className="hover-help-title" data-help="UP, DOWN and UNKNOWN are synchronized from availability. This control only manages the manual DEGRADED override.">Manual degraded</strong><div className="management-action-controls"><Select unstyled aria-label="Manual degraded override" value={degradedAction} onChange={e=>setDegradedAction(e.target.value)}><option value="MARK">Mark DEGRADED</option><option value="CLEAR">Clear override</option></Select><Button unstyled onClick={()=>void updateDegradedOverride()} disabled={!selectedRows.length||working}>Apply</Button></div></div>}
        {canUpdate&&<div className="management-action-group lifecycle-action-group"><strong className="hover-help-title" data-help="Apply a valid lifecycle transition. Decommission and reactivation keep their protected validation rules.">Lifecycle</strong><div className="management-action-controls"><Select unstyled aria-label="Lifecycle state" value={lifecycle} onChange={e=>setLifecycle(e.target.value)}><option value="REGISTERED" disabled>REGISTERED — onboarding only</option><option value="ACTIVE">ACTIVE</option><option value="MAINTENANCE">MAINTENANCE</option><option value="DECOMMISSIONED">DECOMMISSIONED</option></Select><Button unstyled className={lifecycle==="DECOMMISSIONED"?"danger outline":""} onClick={()=>void applyLifecycle()} disabled={!selectedRows.length||working}>Apply</Button></div></div>}
        {canDelete&&<div className="management-action-group recycle-action-group"><strong className="hover-help-title" data-help="Check dependencies, then move selected devices to the recoverable Recycle Bin.">Recycle Bin</strong><div className="management-action-controls"><Button unstyled className="danger recycle-batch-button" onClick={()=>void recycle()} disabled={!selectedRows.length||working}>Move selected to Recycle Bin</Button></div></div>}
      </div>
    </section>}

    <section className="panel management-results-panel">
      <div className="panel-header"><div><h3 className="hover-help-title" data-help="Shows the physical SECTOR device resolved through the CPE/AP hierarchy.">Filtered devices</h3></div><TableExportButton token={props.token} tableId="device_management" filters={{...props.filters,sort_by:props.sort.key,sort_direction:props.sort.direction}} /></div>
      <DataTable viewportClassName="table-wrap" className="management-table"><thead><tr>{canBatchActions&&<th><Input unstyled type="checkbox" aria-label="Select all visible devices" checked={allVisibleSelected} onChange={toggleAll}/></th>}<SortHeader label="Device" sortKey="display_name" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Type" sortKey="device_type_code" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="IP" sortKey="management_ip" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Network" sortKey="network_name" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="City" sortKey="city_name" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Location" sortKey="location_name" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Physical Sector" sortKey="physical_sector_device_name" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="S-VLAN" sortKey="service_vlan_id" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="C-VLAN" sortKey="customer_vlan_id" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Lifecycle" sortKey="lifecycle_state" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/><SortHeader label="Operational" sortKey="operational_state" sort={props.sort} onSort={key=>props.setSort((current:SortState)=>nextSort(current,key))}/></tr></thead><tbody>{props.rows.map(row=><tr key={row.id} className={selected.has(row.id)?"selected-row":""}>{canBatchActions&&<td><Input unstyled type="checkbox" checked={selected.has(row.id)} onChange={()=>toggle(row.id)} aria-label={`Select ${row.display_name}`}/></td>}<td><strong>{row.display_name}</strong>{row.parent_device_name&&<small>Parent: {row.parent_device_name}</small>}</td><td>{row.device_type_code}</td><td className="mono">{row.management_ip||"—"}</td><td>{row.network_name||"—"}</td><td>{row.city_name||"—"}</td><td>{row.location_name||"—"}</td><td>{row.physical_sector_device_name||"—"}</td><td>{row.service_vlan_id??"—"}</td><td>{row.device_type_code==="SECTOR"?(row.customer_vlan_start!=null&&row.customer_vlan_end!=null?`${row.customer_vlan_start}-${row.customer_vlan_end}`:"—"):(row.device_type_code==="CPE"||row.device_type_code==="ACCESS_POINT"?row.customer_vlan_id??"—":"—")}</td><td><Badge value={row.lifecycle_state}/></td><td><Badge value={row.operational_state}/></td></tr>)}<ServerPaginationRow colSpan={canBatchActions?12:11} page={props.page} pageSize={props.pageSize} total={props.total} onPage={props.setPage} onPageSize={size=>{props.setPageSize(size);props.setPage(1)}} itemLabel="devices" /></tbody></DataTable>{!props.rows.length&&<EmptyState text="No devices match the management filters."/>}
    </section>

    <TemplateAssignmentBulkDialog open={templateDialogOpen} token={props.token} devices={selectedRows} permissions={props.permissions} onClose={()=>setTemplateDialogOpen(false)} onApplied={async status=>{await props.onReload();if(status==="SUCCEEDED"){clearSelection();setTemplateDialogOpen(false)}}}/>
  </div>;
}
