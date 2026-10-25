import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import type { Customer, CustomerListRow, PageResult, Service, SortState } from "../../types";

type Options = {
  token: string;
  permissions: string[];
  active: boolean;
  recycleEntity: (entityType: string, id: string, label: string, deletePath: string) => Promise<boolean>;
  setBusy: (value: boolean) => void;
  clearAlerts: () => void;
  setError: (value: string) => void;
  setMessage: (value: string) => void;
  onError: (error: unknown, fallback: string, context?: { action?: string; entityType?: string; entityName?: string }) => void;
};

export function useCustomerWorkspace(options: Options) {
  const optionsRef = useRef(options);
  optionsRef.current = options;
  const dialog = useDialog();
  const [customers, setCustomers] = useState<CustomerListRow[]>([]);
  const [form, setForm] = useState({ customer_code: "", name: "", status: "ACTIVE" });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [customerNameFilter, setCustomerNameFilter] = useState("");
  const [customerServiceFilter, setCustomerServiceFilter] = useState("");
  const [customerSectorFilter, setCustomerSectorFilter] = useState("");
  const [customerServiceVlanFilter, setCustomerServiceVlanFilter] = useState("");
  const [customerCustomerVlanFilter, setCustomerCustomerVlanFilter] = useState("");
  const [sort, setSort] = useState<SortState>({ key: "name", direction: "asc" });
  const [selected, setSelected] = useState<Customer | null>(null);
  const [services, setServices] = useState<Service[]>([]);
  const [serviceForm, setServiceForm] = useState({
    service_code: "", status: "ACTIVE", access_point_device_id: "", customer_vlan_id: "",
  });
  const requestRef = useRef(0);
  const wasActiveRef = useRef(false);
  const debouncedSearch = useDebouncedValue(search, 300);

  useEffect(() => {
    if (options.active && !wasActiveRef.current) {
      setSelected(null);
      setServices([]);
    }
    wasActiveRef.current = options.active;
  }, [options.active]);

  const load = useCallback(async () => {
    const requestId = ++requestRef.current;
    const params = new URLSearchParams({
      page: String(page), page_size: String(pageSize), sort_by: sort.key, sort_direction: sort.direction,
    });
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    if (customerNameFilter) params.set("customer_name", customerNameFilter);
    if (customerServiceFilter) params.set("service_code", customerServiceFilter);
    if (customerSectorFilter) params.set("sector_id", customerSectorFilter);
    if (customerServiceVlanFilter) params.set("service_vlan_id", customerServiceVlanFilter);
    if (customerCustomerVlanFilter) params.set("customer_vlan_id", customerCustomerVlanFilter);
    const result = await apiFetch<PageResult<CustomerListRow>>(`/customers/page?${params.toString()}`, {}, options.token);
    if (requestId !== requestRef.current) return;
    setCustomers(result.items);
    setTotal(result.total);
  }, [customerNameFilter, customerSectorFilter, customerServiceFilter, customerServiceVlanFilter, customerCustomerVlanFilter, debouncedSearch, options.token, page, pageSize, sort]);

  useEffect(() => { setPage(1); }, [debouncedSearch, customerNameFilter, customerServiceFilter, customerSectorFilter, customerServiceVlanFilter, customerCustomerVlanFilter]);
  useEffect(() => {
    if (!options.active || !options.permissions.includes("customer.read")) return;
    void load().catch((error) => optionsRef.current.onError(error, "Unable to load customers."));
  }, [load, options.active, options.permissions]);

  const selectCustomer = useCallback(async (customer: Customer) => {
    setSelected(customer);
    try {
      setServices(await apiFetch<Service[]>(`/customers/${customer.id}/services`, {}, optionsRef.current.token));
    } catch (error) {
      optionsRef.current.onError(error, "Unable to load customer services.");
    }
  }, []);

  const createCustomer = useCallback(async () => {
    const current = optionsRef.current;
    if (!form.customer_code.trim() || !form.name.trim()) return;
    if (!await dialog.confirm({ message: `Create customer ${form.name.trim()}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Customer>("/customers", { method: "POST", body: JSON.stringify({ ...form, metadata: {} }) }, current.token);
      setSelected(body);
      await load();
      current.setMessage("Customer created.");
    } catch (error) { current.onError(error, "Unable to create customer."); }
    finally { current.setBusy(false); }
  }, [dialog, form, load]);

  const updateCustomerStatus = useCallback(async (status: string) => {
    const current = optionsRef.current;
    if (!selected || status === selected.status) return;
    current.setBusy(true);
    try {
      const updated = await apiFetch<Customer>(`/customers/${selected.id}`, { method: "PATCH", body: JSON.stringify({ status }) }, current.token);
      setSelected(updated); await load(); current.setMessage(`Customer status changed to ${status}.`);
    } catch (error) { current.onError(error, "Unable to update customer status."); }
    finally { current.setBusy(false); }
  }, [load, selected]);

  const createService = useCallback(async () => {
    const current = optionsRef.current;
    if (!selected || !serviceForm.service_code.trim() || !serviceForm.access_point_device_id || !serviceForm.customer_vlan_id) {
      current.setError("Customer, service code, access point and Customer VLAN are required."); return;
    }
    if (!await dialog.confirm({ message: `Create service ${serviceForm.service_code.trim()} for ${selected.name}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      await apiFetch<Service>(`/customers/${selected.id}/services`, {
        method: "POST",
        body: JSON.stringify({
          customer_id: selected.id, service_code: serviceForm.service_code.trim(),
          status: serviceForm.status, access_point_device_id: serviceForm.access_point_device_id,
          customer_vlan_id: Number(serviceForm.customer_vlan_id), metadata: {},
        }),
      }, current.token);
      await Promise.all([selectCustomer(selected), load()]);
      current.setMessage("Customer service created.");
    } catch (error) { current.onError(error, "Unable to create customer service."); }
    finally { current.setBusy(false); }
  }, [dialog, load, selectCustomer, selected, serviceForm]);

  const deleteSelected = useCallback(async () => {
    const current = optionsRef.current;
    if (!selected) return;
    try {
      if (await current.recycleEntity("CUSTOMER", selected.id, selected.name, `/customers/${selected.id}`)) {
        setSelected(null); setServices([]); await load(); current.setMessage("Customer moved to Recycle Bin.");
      }
    } catch (error) {
      current.onError(error, "Unable to delete customer.", { action: "delete", entityType: "customer", entityName: selected.name });
    }
  }, [load, selected]);

  const deleteService = useCallback(async (service: Service) => {
    const current = optionsRef.current;
    try {
      if (await current.recycleEntity("CUSTOMER_SERVICE", service.id, service.service_code, `/customers/services/${service.id}`)) {
        if (selected) await selectCustomer(selected);
        await load(); current.setMessage("Customer service moved to Recycle Bin.");
      }
    } catch (error) {
      current.onError(error, "Unable to delete service.", { action: "delete", entityType: "customer service", entityName: service.service_code });
    }
  }, [load, selectCustomer, selected]);

  return {
    customers, total, page, setPage, pageSize, setPageSize, search, setSearch,
    customerNameFilter, setCustomerNameFilter, customerServiceFilter, setCustomerServiceFilter,
    customerSectorFilter, setCustomerSectorFilter, customerServiceVlanFilter, setCustomerServiceVlanFilter,
    customerCustomerVlanFilter, setCustomerCustomerVlanFilter, sort, setSort, selected, services,
    form, setForm, serviceForm, setServiceForm, load, selectCustomer, createCustomer,
    updateCustomerStatus, createService, deleteSelected, deleteService,
  };
}
