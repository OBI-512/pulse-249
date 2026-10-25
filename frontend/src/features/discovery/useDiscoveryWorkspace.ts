import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import { DISCOVERY_DEFAULTS } from "../../constants";
import type { BatchJobDetail, DiscoveryJob, DiscoveryResult, PageResult, SortState } from "../../types";

type UseDiscoveryWorkspaceOptions = {
  token: string;
  permissions: string[];
  active: boolean;
  setBusy: (busy: boolean) => void;
  clearAlerts: () => void;
  setError: (message: string) => void;
  setMessage: (message: string) => void;
  onError: (error: unknown, fallback: string) => void;
  confirm: (message: string) => Promise<boolean>;
  onCandidatesChanged: () => Promise<void>;
};

type SnmpAccessTemplate = {
  id: string;
  name: string;
  protocol: string;
  protocol_variant: string | null;
  is_active: boolean;
  visibility: string;
};

type SnmpCredentialSource = "ACCESS_TEMPLATE" | "ONE_TIME";

function optionalPort(value: string, label: string): number | null {
  if (!value.trim()) return null;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label} port must be blank or an integer between 1 and 65535.`);
  }
  return port;
}

export function useDiscoveryWorkspace(options: UseDiscoveryWorkspaceOptions) {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const [ip, setIp] = useState("");
  const [methods, setMethods] = useState<string[]>(["ICMP"]);
  const [timeout, setTimeout] = useState("2");
  const [httpPort, setHttpPort] = useState("");
  const [httpsPort, setHttpsPort] = useState("");
  const [snmpCredentialSource, setSnmpCredentialSource] = useState<SnmpCredentialSource>("ONE_TIME");
  const [snmpAccessTemplateId, setSnmpAccessTemplateId] = useState("");
  const [snmpAccessTemplates, setSnmpAccessTemplates] = useState<SnmpAccessTemplate[]>([]);
  const [snmpVersion, setSnmpVersion] = useState("2c");
  const [snmpCommunity, setSnmpCommunity] = useState("public");
  const [snmpRetries, setSnmpRetries] = useState("0");
  const [snmpV3Username, setSnmpV3Username] = useState("");
  const [snmpV3SecurityLevel, setSnmpV3SecurityLevel] = useState("noAuthNoPriv");
  const [snmpV3AuthProtocol, setSnmpV3AuthProtocol] = useState("SHA");
  const [snmpV3AuthPassword, setSnmpV3AuthPassword] = useState("");
  const [snmpV3PrivProtocol, setSnmpV3PrivProtocol] = useState("AES");
  const [snmpV3PrivPassword, setSnmpV3PrivPassword] = useState("");
  const [results, setResults] = useState<DiscoveryResult[]>([]);
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [jobTotal, setJobTotal] = useState(0);
  const [jobPage, setJobPage] = useState(1);
  const [jobPageSize, setJobPageSize] = useState(50);
  const [jobSort, setJobSort] = useState<SortState>({ key: "created_at", direction: "desc" });
  const [jobSearch, setJobSearchState] = useState("");
  const [jobStatus, setJobStatusState] = useState("");
  const [jobScopeType, setJobScopeTypeState] = useState("");
  const [methodOptions, setMethodOptions] = useState<string[]>(DISCOVERY_DEFAULTS);
  const [batchIps, setBatchIps] = useState("");
  const [batchCidrs, setBatchCidrs] = useState("");
  const [batchConcurrency, setBatchConcurrency] = useState("25");
  const [batchMaxTargets, setBatchMaxTargets] = useState("1000");
  const [selectedBatchJob, setSelectedBatchJob] = useState<BatchJobDetail | null>(null);
  const [dashboardTotal, setDashboardTotal] = useState(0);
  const [dashboardActive, setDashboardActive] = useState(0);
  const requestRef = useRef(0);

  const fetchMethods = useCallback(async (sessionToken: string, sessionPermissions: string[]) => {
    if (!sessionPermissions.includes("discovery.read")) return DISCOVERY_DEFAULTS;
    const body = await apiFetch<{ methods: string[] }>("/discovery/methods", {}, sessionToken);
    return body.methods || DISCOVERY_DEFAULTS;
  }, []);

  const applyMethodOptions = useCallback((nextMethods: string[]) => {
    setMethodOptions(nextMethods);
  }, []);

  const loadSnmpAccessTemplates = useCallback(async () => {
    if (!options.permissions.includes("access_template.read")) {
      setSnmpAccessTemplates([]);
      setSnmpAccessTemplateId("");
      return;
    }
    const rows = await apiFetch<SnmpAccessTemplate[]>("/access-templates?include_inactive=false", {}, options.token);
    const active = rows.filter((row) => row.protocol === "SNMP" && row.is_active);
    setSnmpAccessTemplates(active);
    setSnmpAccessTemplateId((current) => active.some((row) => row.id === current) ? current : (active[0]?.id || ""));
  }, [options.permissions, options.token]);

  const loadJobs = useCallback(async () => {
    const requestId = ++requestRef.current;
    const params = new URLSearchParams({
      page: String(jobPage),
      page_size: String(jobPageSize),
      sort_by: jobSort.key,
      sort_direction: jobSort.direction,
    });
    if (jobSearch.trim()) params.set("search", jobSearch.trim());
    if (jobStatus) params.set("status", jobStatus);
    if (jobScopeType) params.set("scope_type", jobScopeType);
    const result = await apiFetch<PageResult<DiscoveryJob>>(`/discovery/jobs/page?${params.toString()}`, {}, options.token);
    if (requestId !== requestRef.current) return;
    setJobs(result.items);
    setJobTotal(result.total);
  }, [jobPage, jobPageSize, jobScopeType, jobSearch, jobSort, jobStatus, options.token]);

  const fetchDashboardSnapshot = useCallback(async () => {
    if (!options.permissions.includes("discovery.read")) {
      return { jobs: [] as DiscoveryJob[], total: 0, active: 0 };
    }
    const [recentJobs, stats] = await Promise.all([
      apiFetch<DiscoveryJob[]>("/discovery/jobs?limit=5&offset=0", {}, options.token),
      apiFetch<{ active_jobs: number; discovery_jobs: number }>("/discovery/flush/preview", {}, options.token),
    ]);
    return {
      jobs: recentJobs,
      total: stats.discovery_jobs || 0,
      active: stats.active_jobs || 0,
    };
  }, [options.permissions, options.token]);

  const applyDashboardSnapshot = useCallback((snapshot: { jobs: DiscoveryJob[]; total: number; active: number }) => {
    setJobs(snapshot.jobs);
    setDashboardTotal(snapshot.total);
    setDashboardActive(snapshot.active);
  }, []);

  const run = useCallback(async () => {
    const current = optionsRef.current;
    if (!ip.trim()) {
      current.setError("Enter an IP address.");
      return;
    }
    if (!methods.length) {
      current.setError("Select at least one discovery method.");
      return;
    }
    const timeoutSeconds = Number(timeout);
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > 10) {
      current.setError("Timeout must be greater than 0 and no more than 10 seconds.");
      return;
    }
    let requestedHttpPort: number | null;
    let requestedHttpsPort: number | null;
    try {
      requestedHttpPort = methods.includes("HTTP") ? optionalPort(httpPort, "HTTP") : null;
      requestedHttpsPort = methods.includes("HTTPS") ? optionalPort(httpsPort, "HTTPS") : null;
    } catch (error) {
      current.setError(error instanceof Error ? error.message : "Invalid HTTP/HTTPS port.");
      return;
    }
    if (methods.includes("SNMP")) {
      if (snmpCredentialSource === "ACCESS_TEMPLATE") {
        if (!snmpAccessTemplateId) {
          current.setError("Select an active SNMP Access Template.");
          return;
        }
      } else {
        const retries = Number(snmpRetries);
        if (!Number.isInteger(retries) || retries < 0 || retries > 5) {
          current.setError("SNMP retries must be an integer between 0 and 5.");
          return;
        }
        if (["1", "2c"].includes(snmpVersion) && !snmpCommunity.trim()) {
          current.setError(`Enter the SNMP v${snmpVersion} community string.`);
          return;
        }
        if (snmpVersion === "3") {
          if (!snmpV3Username.trim()) {
            current.setError("Enter the SNMPv3 username.");
            return;
          }
          if (["authNoPriv", "authPriv"].includes(snmpV3SecurityLevel) && !snmpV3AuthPassword) {
            current.setError("Enter the SNMPv3 authentication password.");
            return;
          }
          if (snmpV3SecurityLevel === "authPriv" && !snmpV3PrivPassword) {
            current.setError("Enter the SNMPv3 privacy password.");
            return;
          }
        }
      }
    }
    if (!await current.confirm(`Run discovery against ${ip.trim()} using the selected methods?`)) return;

    current.setBusy(true);
    current.clearAlerts();
    try {
      const usingTemplate = methods.includes("SNMP") && snmpCredentialSource === "ACCESS_TEMPLATE";
      const body = await apiFetch<{ job_id: string; status: string; results: DiscoveryResult[] }>(
        "/discovery/run",
        {
          method: "POST",
          body: JSON.stringify({
            ip_address: ip.trim(),
            methods,
            timeout_seconds: timeoutSeconds,
            http_port: requestedHttpPort,
            https_port: requestedHttpsPort,
            access_template_id: usingTemplate ? snmpAccessTemplateId : null,
            snmp_version: methods.includes("SNMP") && !usingTemplate ? snmpVersion : "2c",
            snmp_community: methods.includes("SNMP") && !usingTemplate && ["1", "2c"].includes(snmpVersion) ? snmpCommunity.trim() : null,
            snmp_retries: methods.includes("SNMP") && !usingTemplate ? Number(snmpRetries) || 0 : 0,
            snmp_v3_username: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" ? snmpV3Username.trim() : null,
            snmp_v3_security_level: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" ? snmpV3SecurityLevel : "noAuthNoPriv",
            snmp_v3_auth_protocol: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" ? snmpV3AuthProtocol : null,
            snmp_v3_auth_password: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" && ["authNoPriv", "authPriv"].includes(snmpV3SecurityLevel) ? snmpV3AuthPassword : null,
            snmp_v3_priv_protocol: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" && snmpV3SecurityLevel === "authPriv" ? snmpV3PrivProtocol : null,
            snmp_v3_priv_password: methods.includes("SNMP") && !usingTemplate && snmpVersion === "3" && snmpV3SecurityLevel === "authPriv" ? snmpV3PrivPassword : null,
          }),
        },
        current.token,
      );
      setResults(body.results || []);
      await Promise.all([current.onCandidatesChanged(), loadJobs()]);
      current.setMessage(`Discovery completed for ${ip.trim()}. ${body.results?.length || 0} result(s) returned.`);
    } catch (error) {
      current.onError(error, "Unable to run discovery.");
    } finally {
      current.setBusy(false);
    }
  }, [httpPort, httpsPort, ip, loadJobs, methods, snmpAccessTemplateId, snmpCommunity, snmpCredentialSource, snmpRetries, snmpV3AuthPassword, snmpV3AuthProtocol, snmpV3PrivPassword, snmpV3PrivProtocol, snmpV3SecurityLevel, snmpV3Username, snmpVersion, timeout]);

  const runBatch = useCallback(async () => {
    const current = optionsRef.current;
    const ips = batchIps.split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean);
    const cidrs = batchCidrs.split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean);
    if (!ips.length && !cidrs.length) {
      current.setError("Provide at least one IP address or CIDR.");
      return;
    }
    if (!methods.length) {
      current.setError("Select at least one discovery method.");
      return;
    }
    if (methods.includes("SNMP") && !snmpAccessTemplateId) {
      current.setError("SNMP batch discovery requires an active SNMP Access Template.");
      return;
    }
    let requestedHttpPort: number | null;
    let requestedHttpsPort: number | null;
    try {
      requestedHttpPort = methods.includes("HTTP") ? optionalPort(httpPort, "HTTP") : null;
      requestedHttpsPort = methods.includes("HTTPS") ? optionalPort(httpsPort, "HTTPS") : null;
    } catch (error) {
      current.setError(error instanceof Error ? error.message : "Invalid HTTP/HTTPS port.");
      return;
    }
    if (!await current.confirm(`Queue batch discovery for ${ips.length} explicit IP(s) and ${cidrs.length} CIDR network(s)?`)) return;

    current.setBusy(true);
    current.clearAlerts();
    try {
      const body = await apiFetch<{ job_id: string; status: string; target_count: number; message: string }>(
        "/discovery/batch/jobs",
        {
          method: "POST",
          body: JSON.stringify({
            ip_addresses: ips,
            cidrs,
            methods,
            timeout_seconds: Number(timeout) || 2,
            http_port: requestedHttpPort,
            https_port: requestedHttpsPort,
            access_template_id: methods.includes("SNMP") ? snmpAccessTemplateId : null,
            concurrency: Number(batchConcurrency) || 25,
            max_targets: Number(batchMaxTargets) || 1000,
          }),
        },
        current.token,
      );
      await loadJobs();
      current.setMessage(`Batch discovery queued successfully for ${body.target_count} target(s).`);
    } catch (error) {
      current.onError(error, "Unable to queue batch discovery.");
    } finally {
      current.setBusy(false);
    }
  }, [batchCidrs, batchConcurrency, batchIps, batchMaxTargets, httpPort, httpsPort, loadJobs, methods, snmpAccessTemplateId, timeout]);

  const openBatchJob = useCallback(async (jobId: string) => {
    const current = optionsRef.current;
    try {
      const detail = await apiFetch<BatchJobDetail>(`/discovery/batch/jobs/${jobId}`, {}, current.token);
      setSelectedBatchJob(detail);
      if (detail.job.status === "COMPLETED") await current.onCandidatesChanged();
    } catch (error) {
      current.onError(error, "Unable to load batch job.");
    }
  }, []);

  const loadJobResults = useCallback(async (job: DiscoveryJob) => {
    const current = optionsRef.current;
    try {
      const jobResults = await apiFetch<DiscoveryResult[]>(`/discovery/jobs/${job.id}/results`, {}, current.token);
      setResults(jobResults);
    } catch (error) {
      current.onError(error, "Unable to load discovery results.");
    }
  }, []);

  const flush = useCallback(async () => {
    const current = optionsRef.current;
    try {
      const preview = await apiFetch<any>("/discovery/flush/preview", {}, current.token);
      if (preview.active_jobs) {
        current.setError("Discovery cannot be flushed while a job is active.");
        return;
      }
      if (!await current.confirm(`Flush ${preview.discovery_jobs} discovery jobs, ${preview.discovery_results} protocol observations and ${preview.unregistered_candidates} unregistered candidates? Registered devices are preserved.`)) return;
      const result = await apiFetch<any>("/discovery/flush", { method: "POST" }, current.token);
      await loadJobs();
      await current.onCandidatesChanged();
      setResults([]);
      current.setMessage(`Discovery flushed: ${result.jobs} jobs, ${result.results} observations, ${result.candidates} candidates.`);
    } catch (error) {
      current.onError(error, "Unable to flush discovery.");
    }
  }, [loadJobs]);

  const setJobSearch = useCallback((value: string) => {
    setJobSearchState(value);
    setJobPage(1);
  }, []);

  const setJobStatus = useCallback((value: string) => {
    setJobStatusState(value);
    setJobPage(1);
  }, []);

  const setJobScopeType = useCallback((value: string) => {
    setJobScopeTypeState(value);
    setJobPage(1);
  }, []);

  useEffect(() => {
    if (!options.active) return;
    if (options.permissions.includes("discovery.read")) {
      void loadJobs().catch((error) => optionsRef.current.onError(error, "Unable to load discovery jobs."));
    }
    if (options.permissions.includes("access_template.read")) {
      void loadSnmpAccessTemplates().catch((error) => optionsRef.current.onError(error, "Unable to load SNMP Access Templates."));
    }
    const timer = options.permissions.includes("discovery.read")
      ? window.setInterval(() => void loadJobs().catch(() => undefined), 15000)
      : null;
    return () => { if (timer !== null) window.clearInterval(timer); };
  }, [loadJobs, loadSnmpAccessTemplates, options.active, options.permissions]);

  return {
    ip,
    setIp,
    methods,
    setMethods,
    methodOptions,
    timeout,
    setTimeout,
    httpPort,
    setHttpPort,
    httpsPort,
    setHttpsPort,
    snmpCredentialSource,
    setSnmpCredentialSource,
    snmpAccessTemplateId,
    setSnmpAccessTemplateId,
    snmpAccessTemplates,
    loadSnmpAccessTemplates,
    snmpVersion,
    setSnmpVersion,
    snmpCommunity,
    setSnmpCommunity,
    snmpRetries,
    setSnmpRetries,
    snmpV3Username,
    setSnmpV3Username,
    snmpV3SecurityLevel,
    setSnmpV3SecurityLevel,
    snmpV3AuthProtocol,
    setSnmpV3AuthProtocol,
    snmpV3AuthPassword,
    setSnmpV3AuthPassword,
    snmpV3PrivProtocol,
    setSnmpV3PrivProtocol,
    snmpV3PrivPassword,
    setSnmpV3PrivPassword,
    results,
    jobs,
    jobTotal,
    jobPage,
    setJobPage,
    jobPageSize,
    setJobPageSize,
    jobSort,
    setJobSort,
    jobSearch,
    setJobSearch,
    jobStatus,
    setJobStatus,
    jobScopeType,
    setJobScopeType,
    batchIps,
    setBatchIps,
    batchCidrs,
    setBatchCidrs,
    batchConcurrency,
    setBatchConcurrency,
    batchMaxTargets,
    setBatchMaxTargets,
    selectedBatchJob,
    dashboardTotal,
    dashboardActive,
    fetchMethods,
    applyMethodOptions,
    loadJobs,
    fetchDashboardSnapshot,
    applyDashboardSnapshot,
    run,
    runBatch,
    openBatchJob,
    loadJobResults,
    flush,
  };
}