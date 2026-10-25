import { PageLayout } from "../design-system/layouts";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../api/client";
import { friendlyCode, friendlyError, friendlyErrorNotice } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";
import { useDialog } from "../components/common/DialogSystem";

import type { SortState } from "../types";
import { nextSort } from "../utils/sorting";
import { useDebouncedValue } from "../hooks/useDebouncedValue";

import { Button, Checkbox, Input, Select } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { PaginationControls } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
type Batch = {
  id: string;
  root_entity_type: string;
  root_entity_id: string;
  root_display_snapshot: Record<string, unknown>;
  status: string;
  deleted_at: string;
  purge_after: string;
  deletion_reason: string | null;
  last_error_code: string | null;
  item_count: number;
};

type Page = { items: Batch[]; total: number; page: number; page_size: number };

function fourDigitChallenge(): string {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(1000 + (values[0] % 9000));
}

export function RecycleBinPage({ token, permissions, refreshKey = 0 }: { token: string; permissions: string[]; refreshKey?: number }) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const [data, setData] = useState<Page>({ items: [], total: 0, page: 1, page_size: 50 });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sort, setSort] = useState<SortState>({ key: "deleted_at", direction: "desc" });
  const [search,setSearch]=useState("");
  const debouncedSearch=useDebouncedValue(search,300);
  const [entityType,setEntityType]=useState("");
  const [statusFilter,setStatusFilter]=useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!error) return;
    feedback.error(error);
    setError("");
  }, [error, feedback]);

  useEffect(() => {
    if (!message) return;
    feedback.success(message);
    setMessage("");
  }, [message, feedback]);

  const canRestore = permissions.includes("recycle_bin.restore");
  const canPurge = permissions.includes("recycle_bin.purge");
  const canAnyAction = canRestore || canPurge;
  const selectedRows = useMemo(() => data.items.filter((item) => selected.has(item.id)), [data.items, selected]);
  const allVisibleSelected = data.items.length > 0 && data.items.every((item) => selected.has(item.id));

  const load = async (targetPage = page, targetPageSize = pageSize) => {
    try {
      const params=new URLSearchParams({page:String(targetPage),page_size:String(targetPageSize),sort_by:sort.key,sort_direction:sort.direction});
      if(debouncedSearch.trim())params.set("search",debouncedSearch.trim());
      if(entityType)params.set("entity_type",entityType);
      if(statusFilter)params.set("status",statusFilter);
      const next = await apiFetch<Page>(`/recycle-bin?${params.toString()}`, {}, token);
      const maxPage = Math.max(1, Math.ceil(next.total / targetPageSize));
      if (targetPage > maxPage) {
        setPage(maxPage);
        return;
      }
      setData(next);
      setError("");
      setSelected((current) => new Set([...current].filter((id) => next.items.some((item) => item.id === id))));
    } catch (err) {
      setError(friendlyError(err, "Unable to load the Recycle Bin."));
    }
  };

  useEffect(()=>{setPage(1);setSelected(new Set())},[debouncedSearch,entityType,statusFilter,pageSize]);
  useEffect(() => { void load(page, pageSize); }, [page, pageSize, sort, debouncedSearch, entityType, statusFilter, refreshKey]);

  const restore = async (batch: Batch) => {
    if (!await dialog.confirm({ title: "Restore item", message: `Restore ${batch.root_entity_type} ${display(batch)} from the Recycle Bin?`, confirmLabel: "Restore" })) return;
    setBusy(true); setError(""); setMessage("");
    try {
      await apiFetch(`/recycle-bin/${batch.id}/restore`, { method: "POST" }, token);
      setMessage(`${display(batch)} was restored successfully.`);
      await load();
    } catch (err) {
      const notice = friendlyErrorNotice(err, "Unable to restore item.", { action: "restore", entityType: batch.root_entity_type, entityName: display(batch) });
      feedback.error(notice.message, notice.title);
    } finally { setBusy(false); }
  };

  const requestChallenge = async (title: string, messageText: string, confirmLabel: string) => {
    const challenge = fourDigitChallenge();
    const confirmation = await dialog.prompt({
      title,
      message: `${messageText}\n\nConfirmation number: ${challenge}`,
      label: "Enter the 4-digit confirmation number",
      inputType: "text",
      inputMode: "numeric",
      maxLength: 4,
      pattern: "[0-9]{4}",
      placeholder: "4-digit number",
      confirmLabel,
      tone: "danger",
      helperText: "Enter the four digits exactly. This action cannot be undone after permanent deletion.",
    });
    if (confirmation === null) return false;
    if (confirmation.trim() !== challenge) {
      feedback.error("The confirmation number did not match. Nothing was permanently deleted.", "Confirmation did not match");
      return false;
    }
    return true;
  };

  const purgeOne = async (batch: Batch) => {
    if (!await requestChallenge("Permanently delete item", `Permanently delete ${batch.root_entity_type} ${display(batch)}?`, "Permanently Delete")) return;
    setBusy(true); setError(""); setMessage("");
    try {
      await apiFetch(`/recycle-bin/${batch.id}?force=true&confirmation=${encodeURIComponent(batch.id)}`, { method: "DELETE" }, token);
      setMessage(`${display(batch)} was permanently deleted.`);
      await load();
    } catch (err) {
      const notice = friendlyErrorNotice(err, "Unable to permanently delete item.", { action: "permanently delete", entityType: batch.root_entity_type, entityName: display(batch) });
      feedback.error(notice.message, notice.title);
    } finally { setBusy(false); }
  };

  const purgeMany = async (batches: Batch[], operationLabel: string) => {
    if (!batches.length) {
      feedback.error("Select one or more Recycle Bin items first.", "Nothing selected");
      return;
    }
    setBusy(true); setError(""); setMessage("");
    const failures: Array<{ batch: Batch; error: unknown }> = [];
    let succeeded = 0;
    for (const batch of batches) {
      try {
        await apiFetch(`/recycle-bin/${batch.id}?force=true&confirmation=${encodeURIComponent(batch.id)}`, { method: "DELETE" }, token);
        succeeded += 1;
      } catch (err) {
        failures.push({ batch, error: err });
      }
    }
    setSelected(new Set());
    await load();
    setBusy(false);
    if (!failures.length) {
      feedback.success(`${succeeded} Recycle Bin item(s) were permanently deleted.`, operationLabel);
      return;
    }
    const first = failures[0];
    const notice = friendlyErrorNotice(first.error, "One or more Recycle Bin items could not be permanently deleted.", { action: "permanently delete", entityType: first.batch.root_entity_type, entityName: display(first.batch) });
    feedback.error(`${succeeded} item(s) were deleted and ${failures.length} could not be deleted. ${display(first.batch)}: ${notice.message}`, `${operationLabel} partially completed`);
  };

  const purgeSelected = async () => {
    if (!selectedRows.length) {
      feedback.error("Select one or more items from the current page before using batch permanent delete.", "Nothing selected");
      return;
    }
    if (!await requestChallenge("Permanently delete selected items", `You are about to permanently delete ${selectedRows.length} selected Recycle Bin item(s). Dependency protection remains active for every item.`, "Delete Selected")) return;
    await purgeMany(selectedRows, "Batch deletion complete");
  };

  const fetchAllActiveBatches = async () => {
    const collected: Batch[] = [];
    let currentPage = 1;
    while (true) {
      const result = await apiFetch<Page>(`/recycle-bin?page=${currentPage}&page_size=500`, {}, token);
      collected.push(...result.items);
      if (collected.length >= result.total || !result.items.length) break;
      currentPage += 1;
    }
    return collected;
  };

  const emptyRecycleBin = async () => {
    if (!canPurge || busy) return;
    setBusy(true);
    let all: Batch[] = [];
    try {
      all = await fetchAllActiveBatches();
    } catch (err) {
      setBusy(false);
      const notice = friendlyErrorNotice(err, "Unable to inspect the Recycle Bin before emptying it.", { action: "empty", entityType: "Recycle Bin" });
      feedback.error(notice.message, notice.title);
      return;
    }
    setBusy(false);
    if (!all.length) {
      feedback.info("The Recycle Bin is already empty.", "Nothing to delete");
      return;
    }
    if (!await requestChallenge("Empty Recycle Bin", `This will attempt to permanently delete all ${all.length} item(s) currently in the Recycle Bin. Items with protected dependencies will remain and will be reported.`, "Empty Recycle Bin")) return;
    await purgeMany(all, "Recycle Bin emptied");
  };

  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const toggleAllVisible = () => setSelected((current) => {
    const next = new Set(current);
    if (allVisibleSelected) data.items.forEach((item) => next.delete(item.id));
    else data.items.forEach((item) => next.add(item.id));
    return next;
  });

  const changePageSize = (size: number) => { setPageSize(size); setPage(1); setSelected(new Set()); };
  const changeSort = (key: string) => { setSort((current) => nextSort(current, key)); setPage(1); setSelected(new Set()); };
  const display = (batch: Batch) => String(batch.root_display_snapshot?.label || batch.root_display_snapshot?.display_name || batch.root_display_snapshot?.name || batch.root_display_snapshot?.code || batch.root_entity_id);

  return <PageLayout className="page recycle-bin-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Restore or permanently remove objects in the Recycle Bin.">Recycle Bin</h2></div><div className="actions"><Button unstyled className="secondary" onClick={() => void load()} disabled={busy}>Refresh</Button>{canPurge && <Button unstyled className="danger" onClick={() => void emptyRecycleBin()} disabled={busy || data.total === 0}>Empty Recycle Bin</Button>}</div></div>

    {canPurge && <section className="panel recycle-batch-toolbar">
      <div className="recycle-selection-summary"><strong>{selectedRows.length}</strong><span>selected on this page</span></div>
      <div className="actions">
        <Button unstyled className="secondary" type="button" onClick={toggleAllVisible} disabled={busy || !data.items.length}>{allVisibleSelected ? "Clear visible selection" : "Select all visible"}</Button>
        <Button unstyled className="danger" type="button" onClick={() => void purgeSelected()} disabled={busy || !selectedRows.length}>Permanently Delete Selected</Button>
      </div>
    </section>}

    <section className="panel"><div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={e=>{setSearch(e.target.value);setPage(1)}} placeholder="Search Recycle Bin..."/><Select unstyled value={entityType} onChange={e=>{setEntityType(e.target.value);setPage(1)}}><option value="">All Entity Types</option>{["NETWORK","CITY","LOCATION","SECTOR","DEVICE","CUSTOMER","CUSTOMER_SERVICE","DEVICE_GROUP","DEVICE_RELATIONSHIP","DEVICE_IP","DEVICE_INTERFACE"].map(value=><option key={value}>{value}</option>)}</Select><Select unstyled value={statusFilter} onChange={e=>{setStatusFilter(e.target.value);setPage(1)}}><option value="">Active Recycle Bin</option><option value="RECYCLED">RECYCLED</option><option value="PURGE_FAILED">PURGE_FAILED</option><option value="RESTORED">RESTORED</option><option value="HISTORY">History</option></Select><TableExportButton token={token} tableId="recycle_batches" filters={{ search: debouncedSearch, entity_type: entityType, status: statusFilter, sort_by: sort.key, sort_direction: sort.direction }}/><ClearFiltersButton disabled={!search&&!entityType&&!statusFilter} onClick={()=>{setSearch("");setEntityType("");setStatusFilter("");setPage(1)}}/></div><DataTable viewportClassName="table-wrap"><thead><tr>{canPurge && <th className="selection-column"><Checkbox unstyled aria-label="Select all visible Recycle Bin items" checked={allVisibleSelected} onChange={toggleAllVisible} /></th>}<SortHeader label="Type" sortKey="root_entity_type" sort={sort} onSort={changeSort}/><SortHeader label="Object" sortKey="display" sort={sort} onSort={changeSort}/><SortHeader label="Deleted" sortKey="deleted_at" sort={sort} onSort={changeSort}/><SortHeader label="Purge after" sortKey="purge_after" sort={sort} onSort={changeSort}/><SortHeader label="Items" sortKey="item_count" sort={sort} onSort={changeSort}/><SortHeader label="Status" sortKey="status" sort={sort} onSort={changeSort}/>{canAnyAction && <th>Actions</th>}</tr></thead><tbody>
      {data.items.map(batch => <tr key={batch.id} className={selected.has(batch.id) ? "selected-row" : ""}>{canPurge && <td className="selection-column"><Checkbox unstyled checked={selected.has(batch.id)} onChange={() => toggle(batch.id)} aria-label={`Select ${display(batch)}`} /></td>}<td>{batch.root_entity_type}</td><td>{display(batch)}</td><td>{new Date(batch.deleted_at).toLocaleString()}</td><td>{new Date(batch.purge_after).toLocaleString()}</td><td>{batch.item_count}</td><td>{batch.status}{batch.last_error_code ? <small className="recycle-status-note">{friendlyCode(batch.last_error_code)}</small> : null}</td>{canAnyAction && <td><div className="actions">{canRestore && <Button unstyled className="small" disabled={busy} onClick={() => void restore(batch)}>Restore</Button>}{canPurge && <Button unstyled className="small danger" disabled={busy} onClick={() => void purgeOne(batch)}>Permanently Delete</Button>}</div></td>}</tr>)}
      {!data.items.length && <tr><td colSpan={6 + (canPurge ? 1 : 0) + (canAnyAction ? 1 : 0)}>Recycle Bin is empty.</td></tr>}
    </tbody><tfoot><tr className="pagination-table-row"><td colSpan={6 + (canPurge ? 1 : 0) + (canAnyAction ? 1 : 0)}><PaginationControls page={page} pageSize={pageSize} total={data.total} onPage={setPage} onPageSize={changePageSize} itemLabel="Recycle Bin items" compact /></td></tr></tfoot></DataTable>
    </section>
  </PageLayout>;
}
