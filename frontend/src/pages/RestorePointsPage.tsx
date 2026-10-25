import { PageLayout } from "../design-system/layouts";
import { useEffect, useRef, useState } from "react";
import { Button, Input, Select } from "../design-system/primitives";
import { apiFetch } from "../api/client";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";
import { useDialog } from "../components/common/DialogSystem";

import { useDebouncedValue } from "../hooks/useDebouncedValue";
import type { SortState } from "../types";
import { nextSort } from "../utils/sorting";

import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
type RestoreAccepted = {
  restore_point_id: string;
  emergency_restore_point_id: string;
  status: string;
  request_id: string | null;
  message: string;
};

type RestorePoint = {
  id: string;
  source: string;
  status: string;
  description: string | null;
  artifact_size: number | null;
  sha256: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  retention_until: string | null;
  pinned: boolean;
  failure_code: string | null;
  failure_message: string | null;
};

export function RestorePointsPage({ token, permissions, refreshKey = 0 }: { token: string; permissions: string[]; refreshKey?: number }) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const [items,setItems]=useState<RestorePoint[]>([]);
  const [total,setTotal]=useState(0);
  const [page,setPage]=useState(1);
  const [pageSize,setPageSize]=useState(50);
  const [description,setDescription]=useState("");
  const [search,setSearch]=useState("");
  const debouncedSearch=useDebouncedValue(search,300);
  const [statusFilter,setStatusFilter]=useState("");
  const [sourceFilter,setSourceFilter]=useState("");
  const [pinnedFilter,setPinnedFilter]=useState("");
  const [sort,setSort]=useState<SortState>({key:"created_at",direction:"desc"});
  const [error,setError]=useState("");
  const [message,setMessage]=useState("");
  const [restoreNotice,setRestoreNotice]=useState("");
  const [restoreWatchId,setRestoreWatchId]=useState<string|null>(null);
  const [busy,setBusy]=useState(false);
  const loadRequestRef=useRef(0);

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

  const canCreate=permissions.includes("restore_points.create");
  const canRestore=permissions.includes("restore_points.restore");
  const canDelete=permissions.includes("restore_points.delete");

  const load=async()=>{const requestId=++loadRequestRef.current;try{const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort_by:sort.key,sort_direction:sort.direction});if(debouncedSearch.trim())params.set("search",debouncedSearch.trim());if(statusFilter)params.set("status",statusFilter);if(sourceFilter)params.set("source",sourceFilter);if(pinnedFilter)params.set("pinned",pinnedFilter);const result=await apiFetch<{items:RestorePoint[];total:number;page:number;page_size:number}>(`/restore-points/page?${params.toString()}`,{},token);if(loadRequestRef.current!==requestId)return;setItems(result.items);setTotal(result.total);setError("")}catch(err){if(loadRequestRef.current===requestId)setError(friendlyError(err,"Unable to load restore points"))}};
  useEffect(()=>{setPage(1)},[debouncedSearch,statusFilter,sourceFilter,pinnedFilter,pageSize]);
  useEffect(()=>{void load()},[page,pageSize,sort.key,sort.direction,debouncedSearch,statusFilter,sourceFilter,pinnedFilter,refreshKey]);
  useEffect(()=>{
    if(!restoreWatchId)return;
    let stopped=false;
    const poll=async()=>{
      try{
        const point=await apiFetch<RestorePoint>(`/restore-points/${restoreWatchId}`,{},token);
        if(stopped)return;
        if(point.status==="FAILED"){
          setRestoreWatchId(null);
          setRestoreNotice("");
          feedback.error(point.failure_message||"The restore did not complete. The running system was kept or recovered safely. Review the restore point before trying again.","Restore failed");
          void load();
        }else if(point.status==="RESTORED"){
          setRestoreWatchId(null);
          setRestoreNotice("");
          feedback.success("The restore completed successfully. You may be signed out because active sessions are intentionally revoked after a full restore.","Restore completed");
          void load();
        }
      }catch{
        // During database replacement the status endpoint may be temporarily
        // unavailable. Keep watching; successful restores revoke this session
        // and the application will return to the login page.
      }
    };
    void poll();
    const timer=window.setInterval(()=>void poll(),2000);
    return()=>{stopped=true;window.clearInterval(timer)};
  },[restoreWatchId,token,feedback]);
  const create=async()=>{setBusy(true);setError("");setMessage("");try{await apiFetch("/restore-points",{method:"POST",body:JSON.stringify({description:description||null})},token);setDescription("");setMessage("Restore point created and verified artifact metadata recorded.");await load()}catch(err){setError(friendlyError(err,"Unable to create restore point"))}finally{setBusy(false)}};
  const verify=async(id:string)=>{setBusy(true);setError("");setMessage("");try{await apiFetch(`/restore-points/${id}/verify`,{method:"POST"},token);setMessage("Restore point verification passed.");await load()}catch(err){setError(friendlyError(err,"Verification failed"))}finally{setBusy(false)}};
  const pin=async(point:RestorePoint)=>{setBusy(true);setError("");try{await apiFetch(`/restore-points/${point.id}/pin`,{method:"PATCH",body:JSON.stringify({pinned:!point.pinned})},token);await load()}catch(err){setError(friendlyError(err,"Unable to update retention protection"))}finally{setBusy(false)}};
  const remove=async(point:RestorePoint)=>{if(!await dialog.confirm({title:"Delete restore point",message:`Delete restore point ${point.id}?`,confirmLabel:"Delete",tone:"danger"}))return;setBusy(true);setError("");try{await apiFetch(`/restore-points/${point.id}`,{method:"DELETE"},token);await load()}catch(err){setError(friendlyError(err,"Unable to delete restore point"))}finally{setBusy(false)}};
  const restore=async(point:RestorePoint)=>{const confirmation=await dialog.prompt({title:"Restore entire system",message:`This replaces the application database with the selected restore point.\nAn emergency snapshot will be created first.\n\nRestore point ID: ${point.id}`,label:"Type the restore point ID exactly",confirmLabel:"Restore system",tone:"danger"});if(confirmation===null)return;const normalizedConfirmation=confirmation.trim();if(normalizedConfirmation!==point.id){feedback.error("The restore point ID does not match the selected restore point. No restore was started.","Restore not started");return;}setBusy(true);setError("");setMessage("");setRestoreNotice("");try{const accepted=await apiFetch<RestoreAccepted>(`/restore-points/${point.id}/restore`,{method:"POST",body:JSON.stringify({confirmation:normalizedConfirmation})},token);const notice=`${accepted.message} The system may enter maintenance mode and sign you out while the restore runs. This page will watch for a failure while your session remains available; after access returns, log in again and confirm the final restore-point status.`;setRestoreWatchId(accepted.restore_point_id);setRestoreNotice(notice);feedback.info(notice,"Restore started");await load()}catch(err){setRestoreNotice("");setError(friendlyError(err,"Restore request failed"))}finally{setBusy(false)}};
  const formatSize=(value:number|null)=>value==null?"-":`${(value/1024/1024).toFixed(2)} MiB`;
  return <PageLayout className="page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage restore points, retention, verification, and full-system restore.">Restore Points</h2></div><Button unstyled className="secondary" onClick={()=>void load()} disabled={busy}>Refresh</Button></div>
    {restoreNotice&&<div className="inline-warning">{restoreNotice}</div>}
    
    {canCreate&&<section className="panel"><h3>Create manual restore point</h3><div className="form-grid two"><label>Description<Input unstyled value={description} onChange={e=>setDescription(e.target.value)} placeholder="Optional reason or checkpoint name"/></label></div><Button unstyled onClick={()=>void create()} disabled={busy}>Create restore point</Button></section>}
    <section className="panel"><div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search restore points..."/><Select unstyled value={sourceFilter} onChange={e=>setSourceFilter(e.target.value)}><option value="">All Sources</option><option>MANUAL</option><option>AUTOMATIC</option><option>EMERGENCY</option></Select><Select unstyled value={statusFilter} onChange={e=>setStatusFilter(e.target.value)}><option value="">All Statuses</option>{["PENDING","CREATING","READY","FAILED","VERIFYING","RESTORING","RESTORED"].map(value=><option key={value}>{value}</option>)}</Select><Select unstyled value={pinnedFilter} onChange={e=>setPinnedFilter(e.target.value)}><option value="">Pinned or Unpinned</option><option value="true">Pinned</option><option value="false">Unpinned</option></Select><TableExportButton token={token} tableId="restore_points" filters={{ search: debouncedSearch, status: statusFilter, source: sourceFilter, pinned: pinnedFilter, sort_by: sort.key, sort_direction: sort.direction }}/><ClearFiltersButton disabled={!search&&!statusFilter&&!sourceFilter&&!pinnedFilter} onClick={()=>{setSearch("");setStatusFilter("");setSourceFilter("");setPinnedFilter("");setPage(1)}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Created" sortKey="created_at" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Source" sortKey="source" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Status" sortKey="status" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Description" sortKey="description" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Size" sortKey="artifact_size" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Retention" sortKey="retention_until" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Pinned" sortKey="pinned" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><th>Actions</th></tr></thead><tbody>
      {items.map((point)=><tr key={point.id}><td>{new Date(point.created_at).toLocaleString()}</td><td>{point.source}</td><td>{point.status}{point.failure_message&&<div className="muted">{point.failure_message}</div>}</td><td>{point.description||"-"}</td><td>{formatSize(point.artifact_size)}</td><td>{point.retention_until?new Date(point.retention_until).toLocaleDateString():"-"}</td><td>{point.pinned?"YES":"NO"}</td><td><div className="actions"><Button unstyled className="small" onClick={()=>void verify(point.id)} disabled={busy}>Verify</Button>{canDelete&&<Button unstyled className="small" onClick={()=>void pin(point)} disabled={busy}>{point.pinned?"Unpin":"Pin"}</Button>}{canRestore&&["READY","RESTORED"].includes(point.status)&&<Button unstyled className="small danger" onClick={()=>void restore(point)} disabled={busy}>Restore system</Button>}{canDelete&&!point.pinned&&<Button unstyled className="small danger" onClick={()=>void remove(point)} disabled={busy}>Delete</Button>}</div></td></tr>)}
      {!items.length&&<tr><td colSpan={8}>No restore points currently exist. Automatic restore points are created according to Settings.</td></tr>}
      <ServerPaginationRow colSpan={8} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={(size)=>{setPageSize(size);setPage(1)}} itemLabel="restore points" />
    </tbody></DataTable></section>
  </PageLayout>;
}
