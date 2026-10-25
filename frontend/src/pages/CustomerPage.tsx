import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { CustomerListRow, Service, ServiceEndpointOption, SortState, PageResult } from "../types";
import { apiFetch } from "../api/client";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { SearchableCombobox, type ComboboxPage, type ComboboxOption } from "../design-system/composites/SearchableSelect";
import { nextSort, sortRows } from "../utils/sorting";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";

import { Button, Input, Select } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow, PaginatedTableRows } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
const CUSTOMER_STATUSES = ["ACTIVE", "SUSPENDED", "INACTIVE"];

type FilterOption = { id:string; label:string; description?:string|null };
function CustomerFilterCombobox({token,kind,value,onChange,placeholder,context}:{token:string;kind:"customer-name"|"service-id"|"sector"|"service-vlan"|"customer-vlan";value:string;onChange:(value:string)=>void;placeholder:string;context?:Record<string,string>}){
  const [selected,setSelected]=useState<ComboboxOption<FilterOption>|null>(null);
  const loadPage=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<FilterOption>>=>{
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)params.set("search",query);if(value)params.set("selected_id",value);for(const [key,item] of Object.entries(context||{})){if(item)params.set(key,item)}
    const result=await apiFetch<PageResult<FilterOption>>(`/customers/filter-options/${kind}?${params.toString()}`,{},token);
    const items=result.items.map(row=>({id:row.id,label:row.label,description:row.description||undefined,data:row}));
    const current=items.find(item=>item.id===value);if(current)setSelected(current);
    return {...result,items};
  },[token,kind,value,context]);
  const fallback=useMemo<ComboboxOption<FilterOption>|null>(()=>value?{id:value,label:kind==="sector"?"Current sector":value}:null,[value,kind]);
  return <SearchableCombobox<FilterOption> value={value} selectedOption={selected?.id===value?selected:fallback} onChange={option=>{setSelected(option);onChange(option?.id||"")}} loadPage={loadPage} placeholder={placeholder} emptyText="No matching values found."/>;
}

export function CustomerPage(props: any) {
  const feedback = useFeedback();
  const permissions = props.permissions || [];
  const canCreate = permissions.includes("customer.create");
  const canUpdate = permissions.includes("customer.update");
  const canDelete = permissions.includes("customer.delete");
  const [serviceSort, setServiceSort] = useState<SortState>({ key: "service_code", direction: "asc" });
  const [serviceSearch, setServiceSearch] = useState("");
  const [serviceStatusFilter, setServiceStatusFilter] = useState("");
  const [customerValidationAttempted, setCustomerValidationAttempted] = useState(false);
  const [serviceValidationAttempted, setServiceValidationAttempted] = useState(false);
  const [endpointOptions, setEndpointOptions] = useState<ServiceEndpointOption[]>([]);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const services = useMemo(() => {
    const query = serviceSearch.trim().toLowerCase();
    const filtered = (props.services as Service[]).filter((item) =>
      (!query || `${item.service_code} ${item.sector_name || ""} ${item.cpe_name || ""} ${item.access_point_name || ""}`.toLowerCase().includes(query))
      && (!serviceStatusFilter || item.status === serviceStatusFilter)
    );
    return sortRows(filtered, serviceSort, (item: Service, key) => item[key as keyof Service]);
  }, [props.services, serviceSort, serviceSearch, serviceStatusFilter]);

  useEffect(() => {
    if (!canCreate) { setEndpointOptions([]); return; }
    let cancelled = false;
    setOptionsLoading(true);
    void apiFetch<ServiceEndpointOption[]>(`/customers/service-options`, {}, props.token)
      .then((rows) => { if (!cancelled) setEndpointOptions(rows); })
      .catch((error) => { if (!cancelled) feedback.error(friendlyError(error, "Unable to load service endpoint options.")); })
      .finally(() => { if (!cancelled) setOptionsLoading(false); });
    return () => { cancelled = true; };
  }, [props.token, feedback, canCreate]);

  const chooseAccessPoint = (accessPointId: string) => {
    props.setServiceForm({ ...props.serviceForm, access_point_device_id: accessPointId });
  };
  const selectedEndpoint = endpointOptions.find((option) => option.access_point_device_id === props.serviceForm.access_point_device_id) || null;
  const customerFilterContext = {
    customer_name:props.customerNameFilter||"", service_code:props.customerServiceFilter||"", sector_id:props.customerSectorFilter||"",
    service_vlan_id:props.customerServiceVlanFilter||"", customer_vlan_id:props.customerCustomerVlanFilter||"",
  };

  return <PageLayout className="customer-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage customers, services, and assigned access equipment.">Customers</h2></div></div>
    <div className="two-column customer-workspace">
      <section className="panel customer-list-panel">
        <div className="panel-header"><div className="customer-panel-heading"><h3 className="hover-help-title" data-help="Find a customer by name, service ID, or serving sector.">Customers</h3><span className="customer-count">{props.total.toLocaleString()} customer(s)</span></div><TableExportButton token={props.token} tableId="customers" filters={{customer_name:props.customerNameFilter,service_code:props.customerServiceFilter,sector_id:props.customerSectorFilter,service_vlan_id:props.customerServiceVlanFilter,customer_vlan_id:props.customerCustomerVlanFilter,sort_by:props.sort.key,sort_direction:props.sort.direction}} /></div>
        <div className="customer-filter-comboboxes">
          <label><span>Customer name</span><CustomerFilterCombobox token={props.token} kind="customer-name" value={props.customerNameFilter} onChange={props.setCustomerNameFilter} placeholder="Search customer name..." context={customerFilterContext}/></label>
          <label><span>Service ID</span><CustomerFilterCombobox token={props.token} kind="service-id" value={props.customerServiceFilter} onChange={props.setCustomerServiceFilter} placeholder="Search service ID..." context={customerFilterContext}/></label>
          <label><span>Sector</span><CustomerFilterCombobox token={props.token} kind="sector" value={props.customerSectorFilter} onChange={props.setCustomerSectorFilter} placeholder="Search physical sector..." context={customerFilterContext}/></label>
          <label><span>S-VLAN</span><CustomerFilterCombobox token={props.token} kind="service-vlan" value={props.customerServiceVlanFilter} onChange={props.setCustomerServiceVlanFilter} placeholder="Search S-VLAN..." context={customerFilterContext}/></label>
          <label><span>C-VLAN</span><CustomerFilterCombobox token={props.token} kind="customer-vlan" value={props.customerCustomerVlanFilter} onChange={props.setCustomerCustomerVlanFilter} placeholder="Search C-VLAN..." context={customerFilterContext}/></label>
        </div>
        {(props.customerNameFilter||props.customerServiceFilter||props.customerSectorFilter||props.customerServiceVlanFilter||props.customerCustomerVlanFilter)&&<div className="filter-clear-row"><ClearFiltersButton onClick={()=>{props.setCustomerNameFilter("");props.setCustomerServiceFilter("");props.setCustomerSectorFilter("");props.setCustomerServiceVlanFilter("");props.setCustomerCustomerVlanFilter("")}}/></div>}
        <DataTable viewportClassName="table-wrap" className="clickable-table customer-list-table">
          <thead><tr>
            <SortHeader label="Customer" sortKey="name" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} />
            <SortHeader label="Service ID" sortKey="service_code" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} />
            <SortHeader label="Sector" sortKey="sector_name" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} />
            <SortHeader label="S-VLAN" sortKey="service_vlan_id" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} />
            <SortHeader label="C-VLAN" sortKey="customer_vlan_id" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} />
          </tr></thead>
          <tbody>
            {(props.customers as CustomerListRow[]).map((customer) => <tr key={customer.id} className={props.selected?.id === customer.id ? "selected-row" : ""} onClick={() => props.onSelect(customer)}>
              <td><strong>{customer.name}</strong></td>
              <td>{customer.service_code || "—"}</td>
              <td>{customer.sector_name || "—"}</td>
              <td>{customer.service_vlan_id ?? "—"}</td>
              <td>{customer.customer_vlan_id ?? "—"}</td>
            </tr>)}
            {!props.customers.length && <tr><td colSpan={5}><EmptyState text="No customers match the current filters." /></td></tr>}
            <ServerPaginationRow colSpan={5} page={props.page} pageSize={props.pageSize} total={props.total} onPage={props.setPage} onPageSize={(size) => { props.setPageSize(size); props.setPage(1); }} itemLabel="customers" />
          </tbody>
        </DataTable>
        {canCreate && <div className={`panel-subsection${customerValidationAttempted ? " validation-attempted" : ""}`}><h4 className="hover-help-title" data-help="Create a customer record before assigning a service.">Create customer</h4><div className="form-grid three"><label><span className="required-field-label">Customer code</span><Input unstyled required value={props.form.customer_code} onChange={e=>props.setForm({...props.form,customer_code:e.target.value})}/></label><label><span className="required-field-label">Name</span><Input unstyled required value={props.form.name} onChange={e=>props.setForm({...props.form,name:e.target.value})}/></label><label>Status<Select unstyled value={props.form.status} onChange={e=>props.setForm({...props.form,status:e.target.value})}>{CUSTOMER_STATUSES.map((status)=><option key={status}>{status}</option>)}</Select></label></div><Button unstyled onClick={() => { const invalid = !props.form.customer_code.trim() || !props.form.name.trim(); setCustomerValidationAttempted(true); props.onCreate(); if (!invalid) setCustomerValidationAttempted(false); }} disabled={props.busy}>Create Customer</Button></div>}
      </section>

      <section className="panel customer-detail-panel">{!props.selected ? <EmptyState text="Select a customer."/> : <>
        <div className="panel-header customer-detail-header">
          <div className="customer-detail-heading">
            <h3>{props.selected.name}</h3>
            <span className="customer-code-line">{props.selected.customer_code}</span>
            <div className="customer-status-under-name">
              {canUpdate ? <label className="compact-select">Status<Select unstyled value={props.selected.status} onChange={(event) => props.onStatusChange(event.target.value)} disabled={props.busy}>{CUSTOMER_STATUSES.map((status) => <option key={status}>{status}</option>)}</Select></label> : <Badge value={props.selected.status} />}
            </div>
          </div>
          {canDelete && <Button unstyled className="small danger customer-delete-button" onClick={props.onDelete}>Delete Customer</Button>}
        </div>

        {canCreate && <div className={`panel-subsection${serviceValidationAttempted ? " validation-attempted" : ""}`}><h4 className="hover-help-title" data-help="Select the customer-facing access point. Its authoritative CPE and sector are derived automatically from topology.">Create service</h4>
          <div className="form-grid two">
            <label><span className="required-field-label">Service ID</span><Input unstyled required value={props.serviceForm.service_code} onChange={e=>props.setServiceForm({...props.serviceForm,service_code:e.target.value})}/></label>
            <label>Status<Select unstyled value={props.serviceForm.status} onChange={e=>props.setServiceForm({...props.serviceForm,status:e.target.value})}><option>ACTIVE</option><option>SUSPENDED</option><option>INACTIVE</option></Select></label>
            <label><span className="required-field-label">Access point</span><Select unstyled required value={props.serviceForm.access_point_device_id} onChange={e=>chooseAccessPoint(e.target.value)} disabled={optionsLoading}><option value="">{optionsLoading ? "Loading access points..." : "Select access point"}</option>{endpointOptions.map((option)=><option key={option.access_point_device_id} value={option.access_point_device_id}>{option.access_point_name} · {option.cpe_name} · {option.sector_name}</option>)}</Select></label>
            <label><span className="required-field-label">Customer VLAN (C-VLAN)</span><Input unstyled required type="number" min={2} max={4094} value={props.serviceForm.customer_vlan_id} onChange={e=>props.setServiceForm({...props.serviceForm,customer_vlan_id:e.target.value})}/></label>
          </div>
          {selectedEndpoint && <div className="derived-context service-derived-context"><div><span>CPE</span><strong>{selectedEndpoint.cpe_name}</strong></div><div><span>Sector</span><strong>{selectedEndpoint.sector_name}</strong></div><div><span>Service VLAN</span><strong>{selectedEndpoint.service_vlan_id ?? "Not configured"}</strong></div><div><span>Allowed C-VLANs</span><strong>{selectedEndpoint.customer_vlan_start != null && selectedEndpoint.customer_vlan_end != null ? `${selectedEndpoint.customer_vlan_start}-${selectedEndpoint.customer_vlan_end}` : "Not configured"}</strong></div></div>}
          <Button unstyled onClick={() => { const invalid = !props.serviceForm.service_code.trim() || !props.serviceForm.access_point_device_id || !props.serviceForm.customer_vlan_id; setServiceValidationAttempted(true); props.onCreateService(); if (!invalid) setServiceValidationAttempted(false); }} disabled={props.busy || optionsLoading}>Create Service</Button>
        </div>}

        <h4 className="hover-help-title" data-help="Shows the service ID and the physical access equipment assigned to this customer.">Services</h4>
        <div className="filter-row compact management-filter-row"><Input unstyled value={serviceSearch} onChange={event=>setServiceSearch(event.target.value)} placeholder="Search services..."/><Select unstyled value={serviceStatusFilter} onChange={event=>setServiceStatusFilter(event.target.value)}><option value="">All Statuses</option>{CUSTOMER_STATUSES.map(status=><option key={status} value={status}>{status}</option>)}</Select><ClearFiltersButton disabled={!serviceSearch&&!serviceStatusFilter} onClick={()=>{setServiceSearch("");setServiceStatusFilter("")}}/><TableExportButton token={props.token} tableId="customer_services" filters={{customer_id:props.selected.id,search:serviceSearch,status:serviceStatusFilter,sort_by:serviceSort.key,sort_direction:serviceSort.direction}} /></div>
        {services.length===0 ? <EmptyState text="No services match the current filters."/> : <DataTable viewportClassName="table-wrap"><thead><tr>
          <SortHeader label="Service ID" sortKey="service_code" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="Sector" sortKey="sector_name" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="S-VLAN" sortKey="service_vlan_id" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="C-VLAN" sortKey="customer_vlan_id" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="CPE" sortKey="cpe_name" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="Access Point" sortKey="access_point_name" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>
          <SortHeader label="Status" sortKey="status" sort={serviceSort} onSort={key=>setServiceSort(c=>nextSort(c,key))}/>{canDelete && <th />}
        </tr></thead><tbody><PaginatedTableRows items={services} colSpan={canDelete ? 8 : 7} resetKey={`${serviceSearch}|${serviceStatusFilter}`} itemLabel="services" renderRow={(service)=><tr key={service.id}><td>{service.service_code}</td><td>{service.sector_name || "—"}</td><td>{service.service_vlan_id ?? "—"}</td><td>{service.customer_vlan_id ?? "—"}</td><td>{service.cpe_name || "—"}</td><td>{service.access_point_name || "—"}</td><td><Badge value={service.status}/></td>{canDelete && <td><Button unstyled className="small danger" onClick={()=>props.onDeleteService(service)}>Delete</Button></td>}</tr>} /></tbody></DataTable>}
      </>}</section>
    </div>
  </PageLayout>;
}
