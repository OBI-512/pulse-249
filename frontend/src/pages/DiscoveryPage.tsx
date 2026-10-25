import { PageLayout } from "../design-system/layouts";
import { useState } from "react";
import type { DiscoveryJob, SortState } from "../types";
import { formatDate } from "../utils/formatting";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { nextSort } from "../utils/sorting";
import { DiscoveryResults } from "./DiscoveryResults";
import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { Button, Checkbox, Input, Select, Textarea } from "../design-system/primitives";

export function DiscoveryPage(props: any) {
  const jobSort = props.jobSort as SortState;
  const setJobSort = props.setJobSort;
  const toggleMethod = (method: string) => props.setMethods((current: string[]) => current.includes(method) ? current.filter((x) => x !== method) : [...current, method]);
  const snmpSelected = props.methods.includes("SNMP");
  const snmpTemplateSource = props.snmpCredentialSource === "ACCESS_TEMPLATE";
  const snmpV3 = props.snmpVersion === "3";
  const snmpAuth = snmpV3 && ["authNoPriv", "authPriv"].includes(props.snmpV3SecurityLevel);
  const snmpPriv = snmpV3 && props.snmpV3SecurityLevel === "authPriv";
  const canRun = props.permissions?.includes("discovery.run");
  const canReadTemplates = props.permissions?.includes("access_template.read");
  const [validationAttempted, setValidationAttempted] = useState(false);

  return (
    <PageLayout className="discovery-page">
      <div className="page-heading">
        <div>
          <h2 className="hover-help-title" data-help="Discover devices, combine protocol evidence, and create review candidates.">Network Discovery</h2>
        </div>
        <div className="button-row"><Button unstyled className="secondary" onClick={()=>props.onRefresh?.()} disabled={props.busy}>Refresh</Button>{props.canFlush&&<Button unstyled className="danger" onClick={props.onFlush} disabled={props.busy}>Flush Discovery</Button>}</div>
      </div>

      {canRun && <div className="discovery-command-grid">
        <section className={`panel command-card${validationAttempted ? " validation-attempted" : ""}`}>
          <div className="panel-header"><div><h3 className="hover-help-title" data-help="Probe one target with multiple discovery protocols.">Single target</h3></div><span className="panel-tag">LIVE</span></div>
          <div className="form-grid">
            <label><span className="required-field-label">IP address</span><Input unstyled required pattern="(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}" title="Enter a valid IPv4 address, for example 192.168.1.10." value={props.ip} onChange={(e) => props.setIp(e.target.value)} placeholder="192.168.0.1" /></label>
            <label>Timeout (seconds)<Input unstyled type="number" min="0.1" max="10" step="0.1" value={props.timeout} onChange={(e) => props.setTimeoutValue(e.target.value)} /></label>
          </div>
          <div className="field-block">
            <span className="field-label">Methods</span>
            <div className="check-grid">{props.methodOptions.map((method: string) => <label className="check-item" key={method}><Checkbox unstyled checked={props.methods.includes(method)} onChange={() => toggleMethod(method)} />{method}</label>)}</div>
          </div>
          {(props.methods.includes("HTTP") || props.methods.includes("HTTPS")) && <div className="form-grid">
            {props.methods.includes("HTTP") && <label>HTTP port (optional)<Input unstyled type="number" min="1" max="65535" step="1" value={props.httpPort} onChange={(e)=>props.setHttpPort(e.target.value)} placeholder="Default: 80" /></label>}
            {props.methods.includes("HTTPS") && <label>HTTPS port (optional)<Input unstyled type="number" min="1" max="65535" step="1" value={props.httpsPort} onChange={(e)=>props.setHttpsPort(e.target.value)} placeholder="Default: 443" /></label>}
          </div>}

          {snmpSelected && (
            <div className="snmp-config-card">
              <div className="snmp-config-heading"><div><strong className="hover-help-title" data-help="Use an Access Template for reusable server-side credentials or one-time credentials for this single request.">SNMP configuration</strong></div><Badge value={snmpTemplateSource ? "Access Template" : `v${props.snmpVersion}`} /></div>
              <div className="form-grid two">
                <label>Credential source<Select unstyled value={props.snmpCredentialSource} onChange={(e) => props.setSnmpCredentialSource(e.target.value)}><option value="ONE_TIME">One-time credentials</option>{canReadTemplates && <option value="ACCESS_TEMPLATE">Access Template</option>}</Select></label>
                {snmpTemplateSource && <label><span className="required-field-label">SNMP Access Template</span><Select unstyled value={props.snmpAccessTemplateId} onChange={(e) => props.setSnmpAccessTemplateId(e.target.value)}><option value="">Select active template...</option>{props.snmpAccessTemplates.map((template: any) => <option key={template.id} value={template.id}>{template.name} ({template.protocol_variant || "SNMP"})</option>)}</Select></label>}
              </div>
              {snmpTemplateSource ? <p className="field-help">Credentials remain server-side. Discovery receives only the selected Access Template ID; secret values are resolved inside the backend process.</p> : <>
                <div className="form-grid three">
                  <label>SNMP version
                    <Select unstyled value={props.snmpVersion} onChange={(e) => props.setSnmpVersion(e.target.value)}>
                      <option value="1">v1</option>
                      <option value="2c">v2c</option>
                      <option value="3">v3</option>
                    </Select>
                  </label>
                  <label>Retries<Input unstyled type="number" min="0" max="5" step="1" value={props.snmpRetries} onChange={(e) => props.setSnmpRetries(e.target.value)} /></label>
                  {!snmpV3 && <label><span className="required-field-label">Community</span><Input unstyled required type="password" value={props.snmpCommunity} onChange={(e) => props.setSnmpCommunity(e.target.value)} autoComplete="off" placeholder={props.snmpVersion === "1" ? "community" : "public"} /></label>}
                </div>

                {snmpV3 && (
                  <>
                    <div className="form-grid">
                      <label><span className="required-field-label">Username</span><Input unstyled required value={props.snmpV3Username} onChange={(e) => props.setSnmpV3Username(e.target.value)} autoComplete="off" placeholder="snmp-user" /></label>
                      <label>Security level
                        <Select unstyled value={props.snmpV3SecurityLevel} onChange={(e) => props.setSnmpV3SecurityLevel(e.target.value)}>
                          <option value="noAuthNoPriv">noAuthNoPriv</option>
                          <option value="authNoPriv">authNoPriv</option>
                          <option value="authPriv">authPriv</option>
                        </Select>
                      </label>
                    </div>
                    {snmpAuth && <div className="form-grid"><label>Authentication protocol<Select unstyled value={props.snmpV3AuthProtocol} onChange={(e) => props.setSnmpV3AuthProtocol(e.target.value)}><option value="SHA">SHA</option><option value="SHA-256">SHA-256</option><option value="MD5">MD5</option></Select></label><label><span className="required-field-label">Authentication password</span><Input unstyled required type="password" value={props.snmpV3AuthPassword} onChange={(e) => props.setSnmpV3AuthPassword(e.target.value)} autoComplete="new-password" /></label></div>}
                    {snmpPriv && <div className="form-grid"><label>Privacy protocol<Select unstyled value={props.snmpV3PrivProtocol} onChange={(e) => props.setSnmpV3PrivProtocol(e.target.value)}><option value="AES">AES</option><option value="DES">DES</option></Select></label><label><span className="required-field-label">Privacy password</span><Input unstyled required type="password" value={props.snmpV3PrivPassword} onChange={(e) => props.setSnmpV3PrivPassword(e.target.value)} autoComplete="new-password" /></label></div>}
                  </>
                )}
              </>}
            </div>
          )}

          <Button unstyled onClick={() => { setValidationAttempted(true); props.onRun(); }} disabled={props.busy}>{props.busy ? "Running..." : "Run Discovery"}</Button>
        </section>

        <section className="panel command-card">
          <div className="panel-header"><div><h3 className="hover-help-title" data-help="Queue discovery for multiple targets.">Batch discovery</h3></div><span className="panel-tag">ASYNC</span></div>
          <label>IP addresses<Textarea unstyled value={props.batchIps} onChange={(e) => props.setBatchIps(e.target.value)} placeholder={"One per line or comma-separated\n192.168.0.1\n192.168.0.2"} /></label>
          <label>CIDR networks<Textarea unstyled value={props.batchCidrs} onChange={(e) => props.setBatchCidrs(e.target.value)} placeholder={"One network per line\n192.168.1.0/24"} /></label>
          <div className="form-grid three"><label>Concurrency<Input unstyled type="number" min="1" max="100" value={props.concurrency} onChange={(e) => props.setConcurrency(e.target.value)} /></label><label>Max targets<Input unstyled type="number" min="1" max="10000" value={props.maxTargets} onChange={(e) => props.setMaxTargets(e.target.value)} /></label><label>Timeout<Input unstyled type="number" min="0.1" max="10" step="0.1" value={props.timeout} onChange={(e) => props.setTimeoutValue(e.target.value)} /></label></div>
          {snmpSelected && <div className="snmp-config-card"><strong>Batch SNMP credentials</strong><label><span className="required-field-label">SNMP Access Template</span><Select unstyled value={props.snmpAccessTemplateId} onChange={(e) => props.setSnmpAccessTemplateId(e.target.value)} disabled={!canReadTemplates}><option value="">Select active template...</option>{props.snmpAccessTemplates.map((template: any) => <option key={template.id} value={template.id}>{template.name} ({template.protocol_variant || "SNMP"})</option>)}</Select></label><p className="field-help">Batch SNMP requires a reusable Access Template. Only the template ID is queued; credentials are decrypted inside the worker immediately before probes run.</p>{!canReadTemplates && <div className="inline-warning">access_template.read is required to select reusable SNMP discovery credentials.</div>}</div>}
          <Button unstyled onClick={props.onBatch} disabled={props.busy}>Queue Batch Discovery</Button>
        </section>
      </div>}

      {props.results.length > 0 && <section className="panel"><div className="panel-header"><div><h3 className="hover-help-title" data-help="Review the information found for each discovered device.">Latest discovery results</h3></div></div><DiscoveryResults results={props.results} token={props.token} /></section>}
      {props.selectedBatchJob && <section className="panel"><div className="panel-header"><div><h3>Batch job detail</h3><span>{props.selectedBatchJob.job.id}</span></div><Badge value={props.selectedBatchJob.job.status} /></div><div className="detail-grid"><div><span>Targets</span><strong>{props.selectedBatchJob.target_count}</strong></div><div><span>Results</span><strong>{props.selectedBatchJob.result_count}</strong></div><div><span>Celery task</span><strong>{props.selectedBatchJob.celery_task_id || "-"}</strong></div></div><DiscoveryResults results={props.selectedBatchJob.results || []} token={props.token} jobId={props.selectedBatchJob.job.id} /></section>}

      <section className="panel"><div className="panel-header"><div><h3 className="hover-help-title" data-help="Shows recent discovery jobs and their results.">Recent discovery jobs</h3></div></div><div className="filter-row compact management-filter-row"><Input unstyled value={props.jobSearch||""} onChange={(e)=>props.setJobSearch(e.target.value)} placeholder="Search discovery jobs..."/><Select unstyled value={props.jobStatus||""} onChange={(e)=>props.setJobStatus(e.target.value)}><option value="">All Statuses</option>{["QUEUED","RUNNING","COMPLETED","FAILED"].map(value=><option key={value}>{value}</option>)}</Select><Select unstyled value={props.jobScopeType||""} onChange={(e)=>props.setJobScopeType(e.target.value)}><option value="">All Scope Types</option>{["IP","CIDR","BATCH"].map(value=><option key={value}>{value}</option>)}</Select><TableExportButton token={props.token} tableId="discovery_jobs" filters={{ search: props.jobSearch || "", status: props.jobStatus || "", scope_type: props.jobScopeType || "", sort_by: jobSort.key, sort_direction: jobSort.direction }}/><ClearFiltersButton disabled={!props.jobSearch&&!props.jobStatus&&!props.jobScopeType} onClick={()=>{props.setJobSearch("");props.setJobStatus("");props.setJobScopeType("");props.setJobPage(1)}}/></div>{props.jobs.length === 0 ? <EmptyState text="No discovery jobs match the current filters." /> : <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Status" sortKey="status" sort={jobSort} onSort={(key) => setJobSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Scope" sortKey="scope" sort={jobSort} onSort={(key) => setJobSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Type" sortKey="type" sort={jobSort} onSort={(key) => setJobSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Created" sortKey="created_at" sort={jobSort} onSort={(key) => setJobSort((current: SortState) => nextSort(current, key))} /><th /></tr></thead><tbody>{(props.jobs as DiscoveryJob[]).map((job) => <tr key={job.id}><td><Badge value={job.status} /></td><td className="scope-cell">{job.scope_value}</td><td>{job.scope_type}</td><td>{formatDate(job.created_at)}</td><td className="actions"><Button unstyled className="small secondary" onClick={() => props.onOpenJobResults(job)}>Results</Button></td></tr>)}<ServerPaginationRow colSpan={5} page={props.jobPage} pageSize={props.jobPageSize} total={props.jobTotal} onPage={props.setJobPage} onPageSize={(size)=>{props.setJobPageSize(size);props.setJobPage(1)}} itemLabel="discovery jobs" /></tbody></DataTable>}</section>
    </PageLayout>
  );
}