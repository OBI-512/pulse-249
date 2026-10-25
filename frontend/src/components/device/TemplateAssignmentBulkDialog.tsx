import { useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import { Button, Input, Select } from "../../design-system/primitives";
import { DataTable } from "../../design-system/data/DataTable";
import {
  SearchableCombobox,
  type ComboboxOption,
  type ComboboxPage,
} from "../../design-system/composites/SearchableSelect";
import { StatusBadge as Badge } from "../../design-system/composites/Status";
import { ModalShell, useDialog } from "../common/DialogSystem";
import { useFeedback } from "../common/FeedbackSystem";
import type { DeviceManagementRow } from "../../types";


type AccessProtocol = "SSH" | "SNMP" | "WEB" | "TELNET";
type AccessOption = {
  id:string;
  name:string;
  protocol:AccessProtocol;
  lifecycle_status:"ACTIVE";
  visibility:"PRIVATE"|"SHARED";
  compatibility:Record<string,unknown>;
  qualification:Record<string,unknown>;
};
type ConfigurationOption = {
  template_id:string;
  template_version_id:string;
  code:string;
  name:string;
  version_number:number;
  content_sha256:string;
  device_type_id:string;
  device_type_code:string;
  vendor:string;
  model:string|null;
  series:string|null;
  adapter_key:string;
  transport:string;
};
type Page<T>={items:T[];total:number;page:number;page_size:number};
type BatchTarget={
  id:string;batch_id:string;device_id:string;target_ordinal:number;
  preview_status:"READY"|"NOOP"|"BLOCKED";
  apply_status:"NOT_APPLIED"|"SUCCEEDED"|"FAILED"|"SKIPPED";
  warnings:Array<{code?:string;[key:string]:unknown}>;
  blockers:Array<{code?:string;[key:string]:unknown}>;
  planned_changes:Record<string,unknown>;
  family_outcomes:Record<string,unknown>;
  failure_code:string|null;failure_message:string|null;
};
type Batch={
  id:string;status:"PREVIEWED"|"APPLYING"|"SUCCEEDED"|"PARTIAL"|"FAILED"|"EXPIRED";
  request_fingerprint:string;target_count:number;ready_count:number;noop_count:number;
  blocked_count:number;succeeded_count:number;failed_count:number;preview_expires_at:string;
};
type BatchDetail={batch:Batch;targets:BatchTarget[]};

type Props={
  open:boolean;
  token:string;
  devices:DeviceManagementRow[];
  permissions:string[];
  onClose:()=>void;
  onApplied:(status:Batch["status"])=>Promise<void>|void;
};

const protocols:AccessProtocol[]=["SSH","SNMP","WEB","TELNET"];

export function TemplateAssignmentBulkDialog(props:Props){
  const dialog=useDialog();
  const feedback=useFeedback();
  const [access,setAccess]=useState<Record<AccessProtocol,ComboboxOption<AccessOption>|null>>({SSH:null,SNMP:null,WEB:null,TELNET:null});
  const [configuration,setConfiguration]=useState<ComboboxOption<ConfigurationOption>|null>(null);
  const [priority,setPriority]=useState("0");
  const [conflictPolicy,setConflictPolicy]=useState("FAIL_ON_CONFLICT");
  const [replaceConfiguration,setReplaceConfiguration]=useState(false);
  const [configurationEnabled,setConfigurationEnabled]=useState(true);
  const [credentialMode,setCredentialMode]=useState("ACCESS_TEMPLATE");
  const [preview,setPreview]=useState<BatchDetail|null>(null);
  const [working,setWorking]=useState(false);

  const canAccess=props.permissions.includes("access_template.read")&&props.permissions.includes("access_template.manage");
  const canConfiguration=props.permissions.includes("device.configuration.template.read")&&props.permissions.includes("device.configuration.template.manage")&&props.permissions.includes("device.configuration.read");
  const selectedById=useMemo(()=>new Map(props.devices.map(device=>[device.id,device])),[props.devices]);
  const selectedCount=props.devices.length;
  const invalidate=()=>setPreview(null);

  const loadAccess=(protocol:AccessProtocol)=>async(query:string,page:number,pageSize:number):Promise<ComboboxPage<AccessOption>>=>{
    const params=new URLSearchParams({protocol,page:String(page),page_size:String(pageSize)});
    if(query.trim())params.set("search",query.trim());
    const result=await apiFetch<Page<AccessOption>>(`/template-assignment-options/access?${params.toString()}`,{},props.token);
    return {...result,items:result.items.map(item=>({
      id:item.id,label:item.name,description:`${item.protocol} · ${item.visibility}`,data:item,
    }))};
  };
  const loadConfiguration=async(query:string,page:number,pageSize:number):Promise<ComboboxPage<ConfigurationOption>>=>{
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize)});
    if(query.trim())params.set("search",query.trim());
    const result=await apiFetch<Page<ConfigurationOption>>(`/template-assignment-options/configuration?${params.toString()}`,{},props.token);
    return {...result,items:result.items.map(item=>({
      id:item.template_version_id,
      label:`${item.name} · v${item.version_number}`,
      description:[item.code,item.device_type_code,item.vendor,item.model].filter(Boolean).join(" · "),
      data:item,
    }))};
  };

  const buildPayload=()=>({
    device_ids:props.devices.map(device=>device.id),
    access_templates:protocols.flatMap(protocol=>{
      const option=access[protocol];
      return option?[{
        template_id:option.id,
        priority:Number(priority)||0,
        conflict_policy:conflictPolicy,
      }]:[];
    }),
    configuration:configuration?{
      template_version_id:configuration.id,
      replace_existing:replaceConfiguration,
      credential_mode:credentialMode,
      enabled:configurationEnabled,
    }:null,
  });

  const runPreview=async()=>{
    if(selectedCount<1){feedback.error("Select one or more devices before previewing template assignment.","No devices selected");return;}
    if(selectedCount>500){feedback.error("Template assignment batches are limited to 500 explicit devices.","Selection too large");return;}
    const payload=buildPayload();
    if(!payload.access_templates.length&&!payload.configuration){feedback.error("Choose at least one Access Template or one Configuration Template version.","No template selected");return;}
    setWorking(true);
    try{
      const result=await apiFetch<BatchDetail>("/template-assignment-batches/preview",{method:"POST",body:JSON.stringify(payload)},props.token);
      setPreview(result);
      feedback.success(`Previewed ${result.batch.target_count} device(s): ${result.batch.ready_count} ready, ${result.batch.noop_count} no-op, ${result.batch.blocked_count} blocked.`,"Template assignment preview ready");
    }catch(error){
      feedback.error(error instanceof Error?error.message:"Unable to preview template assignments.","Template assignment preview failed");
    }finally{setWorking(false)}
  };

  const apply=async()=>{
    if(!preview)return;
    if(!await dialog.confirm({
      title:"Apply template assignments",
      message:`Apply the previewed metadata changes to ${preview.batch.target_count} device(s)? ${preview.batch.blocked_count} blocked target(s) will be skipped. This does not execute device configuration.`,
      confirmLabel:"Apply assignments",
    }))return;
    setWorking(true);
    try{
      const result=await apiFetch<BatchDetail>(`/template-assignment-batches/${preview.batch.id}/apply`,{
        method:"POST",body:JSON.stringify({expected_request_fingerprint:preview.batch.request_fingerprint}),
      },props.token);
      setPreview(result);
      if(result.batch.status==="SUCCEEDED")feedback.success(`${result.batch.succeeded_count} device(s) updated successfully. No configuration was executed.`,"Template assignment complete");
      else if(result.batch.status==="PARTIAL")feedback.error(`${result.batch.succeeded_count} device(s) succeeded and ${result.batch.failed_count} failed. Review the per-device outcomes below.`,"Template assignment partially completed");
      else feedback.error(`No selected device completed successfully. Review the per-device outcomes below.`,"Template assignment failed");
      await props.onApplied(result.batch.status);
    }catch(error){
      feedback.error(error instanceof Error?error.message:"Unable to apply template assignments.","Template assignment failed");
    }finally{setWorking(false)}
  };

  const close=()=>{if(working)return;props.onClose()};
  const terminal=preview&&["SUCCEEDED","PARTIAL","FAILED","EXPIRED"].includes(preview.batch.status);

  return <ModalShell open={props.open} title="Bulk template assignment" eyebrow="TP4 · TEMPLATE ASSIGNMENT" onClose={close} wide footer={<>
    <Button unstyled type="button" className="secondary" onClick={close} disabled={working}>Close</Button>
    {!terminal&&<Button unstyled type="button" className="secondary" onClick={()=>void runPreview()} disabled={working||selectedCount<1||selectedCount>500}>Preview</Button>}
    {preview?.batch.status==="PREVIEWED"&&<Button unstyled type="button" onClick={()=>void apply()} disabled={working}>Apply preview</Button>}
  </>}>
    <div className="management-filter-grid">
      <label>Selected devices<Input unstyled value={String(selectedCount)} readOnly aria-label="Selected device count" /></label>
      {canAccess&&<>
        {protocols.map(protocol=><label key={protocol}>{protocol} Access Template<SearchableCombobox<AccessOption>
          value={access[protocol]?.id||""}
          selectedOption={access[protocol]}
          onChange={option=>{setAccess(current=>({...current,[protocol]:option}));invalidate()}}
          loadPage={loadAccess(protocol)}
          placeholder={`No ${protocol} template / search...`}
          emptyText={`No eligible ${protocol} Access Templates.`}
          disabled={working||Boolean(terminal)}
        /></label>)}
        <label>Access priority<Input unstyled type="number" value={priority} onChange={event=>{setPriority(event.target.value);invalidate()}} disabled={working||Boolean(terminal)} /></label>
        <label>Access conflict policy<Select unstyled value={conflictPolicy} onChange={event=>{setConflictPolicy(event.target.value);invalidate()}} disabled={working||Boolean(terminal)}><option value="FAIL_ON_CONFLICT">Fail on device-level conflict</option><option value="REPLACE_DEVICE_PROTOCOL">Replace owned device-level protocol assignment</option></Select></label>
      </>}
      {canConfiguration&&<>
        <label>Configuration Template<SearchableCombobox<ConfigurationOption>
          value={configuration?.id||""}
          selectedOption={configuration}
          onChange={option=>{setConfiguration(option);invalidate()}}
          loadPage={loadConfiguration}
          placeholder="No configuration template / search..."
          emptyText="No eligible PUBLISHED Configuration Template versions."
          disabled={working||Boolean(terminal)}
        /></label>
        <label>Configuration credentials<Select unstyled value={credentialMode} onChange={event=>{setCredentialMode(event.target.value);invalidate()}} disabled={working||Boolean(terminal)||!configuration}><option value="ACCESS_TEMPLATE">Access Template</option><option value="REMOTE_ACCESS_PROFILE">Remote Access Profile</option><option value="PRESERVE_EXISTING">Preserve existing binding credentials</option></Select></label>
        <label><span>Replace existing configuration binding</span><Input unstyled type="checkbox" checked={replaceConfiguration} onChange={event=>{setReplaceConfiguration(event.target.checked);invalidate()}} disabled={working||Boolean(terminal)||!configuration}/></label>
        <label><span>Enable configuration binding now</span><Input unstyled type="checkbox" checked={configurationEnabled} onChange={event=>{setConfigurationEnabled(event.target.checked);invalidate()}} disabled={working||Boolean(terminal)||!configuration}/></label>
      </>}
    </div>

    {!canAccess&&!canConfiguration&&<p className="field-help">Your account does not have template-management permissions for bulk assignment.</p>}
    {selectedCount>500&&<p className="field-help">Reduce the selection to 500 devices or fewer before previewing.</p>}
    {preview&&<section className="panel management-results-panel">
      <div className="panel-header"><div><h3>Preview / outcome</h3><small className="mono">{preview.batch.id}</small></div><Badge value={preview.batch.status}/></div>
      <div className="filter-summary management-filter-summary">
        <div><strong>{preview.batch.ready_count}</strong><span>ready</span></div>
        <div><strong>{preview.batch.noop_count}</strong><span>no-op</span></div>
        <div><strong>{preview.batch.blocked_count}</strong><span>blocked</span></div>
        <div><strong>{preview.batch.succeeded_count}</strong><span>succeeded</span></div>
        <div><strong>{preview.batch.failed_count}</strong><span>failed</span></div>
      </div>
      <DataTable viewportClassName="table-wrap" className="management-table"><thead><tr><th>Device</th><th>Preview</th><th>Apply</th><th>Warnings / blockers / failure</th></tr></thead><tbody>
        {preview.targets.slice(0,100).map(target=>{
          const device=selectedById.get(target.device_id);
          const notes=[...target.warnings.map(item=>item.code||"WARNING"),...target.blockers.map(item=>item.code||"BLOCKED"),target.failure_code,target.failure_message].filter(Boolean).join(" · ");
          return <tr key={target.id}><td><strong>{device?.display_name||target.device_id}</strong>{device?.management_ip&&<small className="mono">{device.management_ip}</small>}</td><td><Badge value={target.preview_status}/></td><td><Badge value={target.apply_status}/></td><td>{notes||"—"}</td></tr>;
        })}
      </tbody></DataTable>
      {preview.targets.length>100&&<p className="field-help">Showing the first 100 per-device outcomes of {preview.targets.length}. The batch detail API retains all outcomes.</p>}
      <p className="field-help">Preview fingerprint: <span className="mono">{preview.batch.request_fingerprint}</span></p>
    </section>}
  </ModalShell>;
}
