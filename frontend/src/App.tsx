import { useEffect, useState } from "react";
import "./styles.css";
import "./user-security-phase.css";
import type { CandidateSummary, Device, Health, OperationsDashboard, Page } from "./types";
import { apiFetch } from "./api/client";
import { AppShell } from "./app/AppShell";
import { buildNavigation } from "./app/navigation";
import { LoginPage } from "./pages/LoginPage";
import { AuthorizedUseNotice } from "./components/common/AuthorizedUseNotice";
import { PasswordChangeRequired } from "./components/common/PasswordChangeRequired";
import { OverviewPage } from "./pages/OverviewPage";
import { AlarmPage } from "./pages/AlarmPage";
import { MaintenancePage } from "./pages/MaintenancePage";
import { DiscoveryPage } from "./pages/DiscoveryPage";
import { CandidatePage } from "./pages/CandidatePage";
import { DevicePage } from "./pages/DevicePage";
import { ConfigurationPage } from "./pages/ConfigurationPage";
import { NetworkPage } from "./pages/NetworkPage";
import { GroupPage } from "./pages/GroupPage";
import { CustomerPage } from "./pages/CustomerPage";
import { TopologyPage } from "./pages/TopologyPage";
import { UserManagementPage } from "./pages/UserManagementPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AccountPage } from "./pages/AccountPage";
import { RecycleBinPage } from "./pages/RecycleBinPage";
import { RestorePointsPage } from "./pages/RestorePointsPage";
import { LogsPage } from "./pages/LogsPage";
import { DataReportingPage } from "./pages/DataReportingPage";
import { useDialog } from "./components/common/DialogSystem";
import { useFeedback } from "./components/common/FeedbackSystem";
import { friendlyErrorNotice } from "./utils/feedback";
import type { ThemeMode } from "./components/common/AppChrome";
import { canAccessPage } from "./utils/permissions";
import { useSession } from "./auth/useSession";
import { SessionExpiryDialog } from "./auth/SessionExpiryDialog";
import { useDiscoveryWorkspace } from "./features/discovery/useDiscoveryWorkspace";
import { useReferenceData } from "./features/reference/useReferenceData";
import { useRecycleAction } from "./features/recycle-bin/useRecycleAction";
import { useCustomerWorkspace } from "./features/customers/useCustomerWorkspace";
import { useDeviceWorkspace } from "./features/devices/useDeviceWorkspace";
import { useCandidateWorkspace } from "./features/candidates/useCandidateWorkspace";
import { useTopologyWorkspace } from "./features/topology/useTopologyWorkspace";

export default function App() {
  const dialog = useDialog();
  const feedback = useFeedback();
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem("fttw_theme");
    return saved === "light" || saved === "night" || saved === "operations" ? saved : "operations";
  });
  const [page, setPage] = useState<Page>("overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [dashboardCandidateSummary, setDashboardCandidateSummary] = useState<CandidateSummary>({ total: 0, counts: { NEW: 0, APPROVED: 0, REJECTED: 0, REGISTERED: 0 } });
  const [operationsDashboard, setOperationsDashboard] = useState<OperationsDashboard | null>(null);
  const [dashboardLastUpdated, setDashboardLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [viewRefreshKey, setViewRefreshKey] = useState(0);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme === "night" ? "dark" : "light";
    localStorage.setItem("fttw_theme", theme);
  }, [theme]);

  const clearAlerts = () => { setError(""); setMessage(""); };
  const handleError = (err: unknown, fallback: string, context?: { action?: string; entityType?: string; entityName?: string }) => {
    const notice = friendlyErrorNotice(err, fallback, context);
    feedback.error(notice.message, notice.title);
  };

  useEffect(() => { if (error) { feedback.error(error); setError(""); } }, [error, feedback]);
  useEffect(() => { if (message) { feedback.success(message); setMessage(""); } }, [message, feedback]);

  const {
    token, currentUser, authorizedUseAcknowledgedFor,
    loginUsername, loginPassword, loginRememberMe, loginBusy, loginError,
    sessionExtensionOffer, sessionExtensionBusy,
    setLoginUsername, setLoginPassword, setLoginRememberMe,
    login, logout, extendCurrentSession, declineSessionExtension, completeRequiredPasswordChange, acknowledgeAuthorizedUse, clearLocalSession,
  } = useSession({
    onLoginStart: clearAlerts,
    onLoginSuccess: () => setMessage("Signed in successfully."),
    onSignedOut: () => setPage("overview"),
  });

  const permissions = currentUser?.permissions ?? [];
  const recycleEntity = useRecycleAction(token);
  const references = useReferenceData({ token, permissions, page, onError: handleError });
  const customers = useCustomerWorkspace({
    token, permissions, active: page === "customers", recycleEntity,
    setBusy, clearAlerts, setError, setMessage, onError: handleError,
  });
  const devices = useDeviceWorkspace({
    token, permissions, active: page === "devices", types: references.types, recycleEntity,
    setBusy, clearAlerts, setError, setMessage, onError: handleError,
  });

  async function loadReferenceData(sessionToken: string, sessionPermissions: string[]) {
    const [core, discoveryMethods] = await Promise.all([
      references.fetchCore(sessionToken, sessionPermissions),
      discovery.fetchMethods(sessionToken, sessionPermissions),
    ]);
    references.applyCore(core);
    discovery.applyMethodOptions(discoveryMethods);
  }

  const candidates = useCandidateWorkspace({
    token, permissions, active: page === "candidates", types: references.types,
    setBusy, clearAlerts, setError, setMessage, onError: handleError,
    onReferenceRefresh: () => loadReferenceData(token, permissions),
    onDevicesChanged: devices.loadDevices,
  });

  const discovery = useDiscoveryWorkspace({
    token, permissions, active: page === "discovery",
    setBusy, clearAlerts, setError, setMessage, onError: handleError,
    confirm: (confirmMessage) => dialog.confirm({ message: confirmMessage }),
    onCandidatesChanged: candidates.loadCandidates,
  });

  const topology = useTopologyWorkspace({
    token, recycleEntity, onDevicesChanged: devices.loadDevices, setMessage, onError: handleError,
  });

  const refreshHealth = async () => {
    try { setHealth(await apiFetch<Health>("/health")); }
    catch { setHealth(null); }
  };

  const loadDashboardSnapshot = async () => {
    if (!currentUser) return;
    const can = (permission: string) => currentUser.permissions.includes(permission);
    const [candidateSummary, deviceSummary, discoverySnapshot] = await Promise.all([
      can("candidate.read")
        ? apiFetch<CandidateSummary>("/device-candidates/summary", {}, token)
        : Promise.resolve({ total: 0, counts: { NEW: 0, APPROVED: 0, REJECTED: 0, REGISTERED: 0 } } as CandidateSummary),
      can("device.read")
        ? apiFetch<OperationsDashboard>("/operations-dashboard", {}, token)
        : Promise.resolve(null),
      discovery.fetchDashboardSnapshot(),
    ]);
    setDashboardCandidateSummary(candidateSummary);
    setOperationsDashboard(deviceSummary);
    discovery.applyDashboardSnapshot(discoverySnapshot);
    setDashboardLastUpdated(new Date());
  };

  const initialLoad = async () => {
    if (!currentUser) return;
    setBusy(true); clearAlerts();
    try { await Promise.all([refreshHealth(), loadReferenceData(token, currentUser.permissions)]); }
    catch (err) { handleError(err, "Unable to load the FTTW application data."); }
    finally { setBusy(false); }
  };

  useEffect(() => {
    if (!currentUser) return;
    if (!canAccessPage(page, currentUser.permissions)) setPage("overview");
  }, [currentUser, page]);

  useEffect(() => { if (currentUser) void initialLoad(); }, [currentUser]);

  useEffect(() => {
    if (!token || !currentUser) return;
    const timer = window.setInterval(() => { void refreshHealth(); }, 15000);
    return () => window.clearInterval(timer);
  }, [token, currentUser, page]);

  useEffect(() => {
    if (!token || !currentUser || page !== "overview") return;
    if (currentUser.permissions.includes("geo.read")) {
      void references.loadCrossNetworkGeography()
        .catch((err) => handleError(err, "Unable to load dashboard geography."));
    }
    void loadDashboardSnapshot().catch((err) => handleError(err, "Unable to refresh dashboard snapshot."));
    const timer = window.setInterval(() => { void loadDashboardSnapshot().catch(() => undefined); }, 15000);
    return () => window.clearInterval(timer);
  }, [token, currentUser, page]);

  useEffect(() => {
    if (!currentUser) return;
    if (page === "candidates" && currentUser.permissions.includes("candidate.read") && candidates.selected) {
      void candidates.selectCandidate(candidates.selected);
    } else if (page === "devices" && currentUser.permissions.includes("device.read")) {
      if (currentUser.permissions.includes("group.read")) void references.loadGroups().catch((err) => handleError(err, "Unable to load groups."));
      if (devices.selected) void devices.loadDetails(devices.selected);
    } else if (page === "groups" && currentUser.permissions.includes("group.read")) {
      void references.loadGroups().catch((err) => handleError(err, "Unable to load group workspace data."));
    } else if (page === "topology" && currentUser.permissions.includes("group.read")) {
      void references.loadGroups().catch((err) => handleError(err, "Unable to load topology groups."));
    }
  }, [page, token, currentUser]);

  const refreshCurrentView = async () => {
    if (!currentUser) return;
    const can = (permission: string) => currentUser.permissions.includes(permission);
    setBusy(true);
    try {
      await refreshHealth();
      if (page === "overview") {
        await Promise.all([
          can("network.read") ? references.loadNetworks() : Promise.resolve(),
          can("geo.read")
            ? references.loadCrossNetworkGeography()
            : Promise.resolve(),
          loadDashboardSnapshot(),
        ]);
      } else if (page === "discovery" && can("discovery.read")) {
        await Promise.all([
          discovery.loadJobs(),
          can("access_template.read") ? discovery.loadSnmpAccessTemplates() : Promise.resolve(),
        ]);
      } else if (page === "candidates" && can("candidate.read")) {
        await Promise.all([candidates.loadCandidates(), can("geo.read") ? references.loadCrossNetworkGeography() : Promise.resolve()]);
        if (candidates.selected) await candidates.selectCandidate(candidates.selected);
      } else if (page === "devices" && can("device.read")) {
        await Promise.all([
          devices.section === "management" ? devices.loadManagement() : devices.loadDevices(),
          can("group.read") ? references.loadGroups() : Promise.resolve(),
          can("geo.read") ? references.loadCrossNetworkGeography() : Promise.resolve(),
        ]);
      } else if (page === "groups" && can("group.read")) {
        await Promise.all([references.loadGroups(), can("geo.read") ? references.loadCrossNetworkGeography() : Promise.resolve()]);
      } else if (page === "customers" && can("customer.read")) {
        await Promise.all([customers.load(), can("geo.read") ? references.loadCrossNetworkGeography() : Promise.resolve()]);
        if (customers.selected) await customers.selectCustomer(customers.selected);
      } else if (page === "topology" && can("topology.read")) {
        await Promise.all([can("group.read") ? references.loadGroups() : Promise.resolve(), references.loadTopologyScopeGeography()]);
      }
      setViewRefreshKey((value) => value + 1);
    } catch (err) { handleError(err, "Unable to refresh the current view."); }
    finally { setBusy(false); }
  };

  if (!currentUser) {
    return <LoginPage username={loginUsername} password={loginPassword} rememberMe={loginRememberMe}
      setUsername={setLoginUsername} setPassword={setLoginPassword} setRememberMe={setLoginRememberMe}
      busy={loginBusy} error={loginError} onSubmit={() => void login()} />;
  }
  if (currentUser.must_change_password) {
    return <PasswordChangeRequired token={token} username={currentUser.username} reason={currentUser.password_change_reason}
      onChanged={completeRequiredPasswordChange} onLogout={logout} />;
  }
  if (authorizedUseAcknowledgedFor !== currentUser.id) return <AuthorizedUseNotice onAcknowledge={acknowledgeAuthorizedUse} />;

  const nav = buildNavigation(currentUser.permissions);
  const overview = dashboardCandidateSummary.counts;

  return (
    <>
    <AppShell user={currentUser} health={health} nav={nav} page={page} busy={busy} theme={theme} onTheme={setTheme}
      onPage={(nextPage) => { clearAlerts(); setPage(nextPage); }} onRefresh={() => void refreshCurrentView()} onLogout={() => void logout()}>

      {page === "overview" && <OverviewPage dashboard={operationsDashboard} networks={references.networks}
        locationTotal={references.scopeLocations.length} discoveryTotal={discovery.dashboardTotal} activeDiscovery={discovery.dashboardActive} counts={overview}
        lastUpdated={dashboardLastUpdated} onPage={setPage} permissions={currentUser.permissions} />}

      {page === "alarms" && currentUser.permissions.includes("alarm.read") && <AlarmPage token={token} currentUserId={currentUser.id} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}

      {page === "maintenance" && currentUser.permissions.includes("maintenance.read") && <MaintenancePage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}

      {page === "discovery" && <DiscoveryPage
        token={token}
        ip={discovery.ip} setIp={discovery.setIp} methods={discovery.methods} setMethods={discovery.setMethods} methodOptions={discovery.methodOptions}
        timeout={discovery.timeout} setTimeoutValue={discovery.setTimeout} httpPort={discovery.httpPort} setHttpPort={discovery.setHttpPort} httpsPort={discovery.httpsPort} setHttpsPort={discovery.setHttpsPort}
        snmpCredentialSource={discovery.snmpCredentialSource} setSnmpCredentialSource={discovery.setSnmpCredentialSource}
        snmpAccessTemplateId={discovery.snmpAccessTemplateId} setSnmpAccessTemplateId={discovery.setSnmpAccessTemplateId} snmpAccessTemplates={discovery.snmpAccessTemplates}
        snmpVersion={discovery.snmpVersion} setSnmpVersion={discovery.setSnmpVersion}
        snmpCommunity={discovery.snmpCommunity} setSnmpCommunity={discovery.setSnmpCommunity} snmpRetries={discovery.snmpRetries} setSnmpRetries={discovery.setSnmpRetries}
        snmpV3Username={discovery.snmpV3Username} setSnmpV3Username={discovery.setSnmpV3Username} snmpV3SecurityLevel={discovery.snmpV3SecurityLevel} setSnmpV3SecurityLevel={discovery.setSnmpV3SecurityLevel}
        snmpV3AuthProtocol={discovery.snmpV3AuthProtocol} setSnmpV3AuthProtocol={discovery.setSnmpV3AuthProtocol} snmpV3AuthPassword={discovery.snmpV3AuthPassword} setSnmpV3AuthPassword={discovery.setSnmpV3AuthPassword}
        snmpV3PrivProtocol={discovery.snmpV3PrivProtocol} setSnmpV3PrivProtocol={discovery.setSnmpV3PrivProtocol} snmpV3PrivPassword={discovery.snmpV3PrivPassword} setSnmpV3PrivPassword={discovery.setSnmpV3PrivPassword}
        results={discovery.results} jobs={discovery.jobs} jobTotal={discovery.jobTotal} jobPage={discovery.jobPage} setJobPage={discovery.setJobPage}
        jobPageSize={discovery.jobPageSize} setJobPageSize={discovery.setJobPageSize} jobSort={discovery.jobSort} setJobSort={discovery.setJobSort}
        jobSearch={discovery.jobSearch} setJobSearch={discovery.setJobSearch} jobStatus={discovery.jobStatus} setJobStatus={discovery.setJobStatus}
        jobScopeType={discovery.jobScopeType} setJobScopeType={discovery.setJobScopeType} batchIps={discovery.batchIps} setBatchIps={discovery.setBatchIps}
        batchCidrs={discovery.batchCidrs} setBatchCidrs={discovery.setBatchCidrs} concurrency={discovery.batchConcurrency} setConcurrency={discovery.setBatchConcurrency}
        maxTargets={discovery.batchMaxTargets} setMaxTargets={discovery.setBatchMaxTargets} selectedBatchJob={discovery.selectedBatchJob}
        onRun={discovery.run} onBatch={discovery.runBatch} onOpenBatch={discovery.openBatchJob} onOpenJobResults={discovery.loadJobResults}
        onFlush={discovery.flush} onRefresh={() => void Promise.all([discovery.loadJobs(), discovery.loadSnmpAccessTemplates()])} canFlush={currentUser.permissions.includes("discovery.flush")}
        busy={busy} permissions={currentUser.permissions} />}

      {page === "candidates" && <CandidatePage
        token={token} candidates={candidates.candidates} count={candidates.count} page={candidates.page} setPage={candidates.setPage}
        pageSize={candidates.pageSize} setPageSize={candidates.setPageSize} sort={candidates.sort} setSort={candidates.setSort}
        filter={candidates.filter} setFilter={candidates.setFilter} search={candidates.search} setSearch={candidates.setSearch}
        typeFilter={candidates.typeFilter} setTypeFilter={candidates.setTypeFilter} selected={candidates.selected} types={references.types}
        networks={references.scopeNetworks} cities={references.scopeCities} locations={references.scopeLocations} sectors={references.scopeSectors}
        audit={candidates.audit} ip={candidates.ip} setIp={candidates.setIp} name={candidates.name} setName={candidates.setName}
        hostname={candidates.hostname} setHostname={candidates.setHostname} vendorValue={candidates.vendor} setVendorValue={candidates.setVendor}
        modelValue={candidates.model} setModelValue={candidates.setModel} serialNumber={candidates.serialNumber} setSerialNumber={candidates.setSerialNumber}
        managementProtocol={candidates.managementProtocol} setManagementProtocol={candidates.setManagementProtocol} typeId={candidates.typeId} setTypeId={candidates.setTypeId}
        note={candidates.note} setNote={candidates.setNote} networkId={candidates.networkId} setNetworkId={candidates.setNetworkId}
        cityId={candidates.cityId} setCityId={candidates.setCityId} locationId={candidates.locationId} setLocationId={candidates.setLocationId}
        sectorId={candidates.sectorId} setSectorId={candidates.setSectorId}
        targetDeviceId={candidates.targetDeviceId} setTargetDeviceId={candidates.setTargetDeviceId} setRelationshipType={candidates.setRelationshipType}
        setRelationshipDirection={candidates.setRelationshipDirection} onSelect={(candidate) => void candidates.selectCandidate(candidate)}
        onSave={candidates.saveReview} onApprove={candidates.approve} onReject={candidates.reject} onReopen={candidates.reopen} onRegister={candidates.register}
        busy={busy} permissions={currentUser.permissions} />}

      {page === "devices" && <DevicePage
        token={token} section={devices.section} setSection={devices.setSection} devices={devices.devices} deviceTotal={devices.deviceTotal}
        devicePage={devices.devicePage} setDevicePage={devices.setDevicePage} devicePageSize={devices.devicePageSize} setDevicePageSize={devices.setDevicePageSize}
        deviceSort={devices.deviceSort} setDeviceSort={devices.setDeviceSort} managementRows={devices.managementRows} managementTotal={devices.managementTotal}
        managementPage={devices.managementPage} setManagementPage={devices.setManagementPage} managementPageSize={devices.managementPageSize} setManagementPageSize={devices.setManagementPageSize}
        managementSort={devices.managementSort} setManagementSort={devices.setManagementSort} managementFilters={devices.managementFilters} setManagementFilters={devices.setManagementFilters}
        groups={references.groups} types={references.types} search={devices.search} setSearch={devices.setSearch} lifecycle={devices.lifecycle} setLifecycle={devices.setLifecycle}
        operational={devices.operational} setOperational={devices.setOperational} deviceType={devices.deviceType} setDeviceType={devices.setDeviceType}
        inventoryServiceVlan={devices.inventoryServiceVlan} setInventoryServiceVlan={devices.setInventoryServiceVlan}
        inventoryCustomerVlan={devices.inventoryCustomerVlan} setInventoryCustomerVlan={devices.setInventoryCustomerVlan}
        selected={devices.selected} form={devices.form} setForm={devices.setForm} ips={devices.ips} interfaces={devices.interfaces} placement={devices.placement}
        domainContext={devices.domainContext} placementForm={devices.placementForm} setPlacementForm={devices.setPlacementForm}
        networks={references.networks} customers={customers.customers} cities={references.cities} locations={references.locations} sectors={references.sectors}
        creationNetworks={references.scopeNetworks} creationCities={references.scopeCities} creationLocations={references.scopeLocations} creationSectors={references.scopeSectors}
        loadCities={references.loadCities} loadLocations={references.loadLocations} loadSectors={references.loadSectors}
        statusForm={devices.statusForm} setStatusForm={devices.setStatusForm} ipForm={devices.ipForm} setIpForm={devices.setIpForm}
        interfaceForm={devices.interfaceForm} setInterfaceForm={devices.setInterfaceForm} onSelect={(device: Device) => void devices.loadDetails(device)}
        onNew={devices.startNew} onCreate={devices.createDevice} onUpdate={devices.updateDevice} onStatus={devices.updateStatus}
        onDecommission={devices.decommission} onReactivate={devices.reactivate} onDelete={devices.deleteDevice} onTestAccessibility={devices.testAccessibility}
        onAddIp={devices.addIp} onUpdateIp={devices.updateIp} onDeleteIp={devices.deleteIp} onAddInterface={devices.addInterface}
        onDeleteInterface={devices.deleteInterface} onPlacement={devices.updatePlacement} onReloadManagement={devices.loadManagement}
        busy={busy} permissions={currentUser.permissions} />}

      {page === "configuration" && currentUser.permissions.includes("device.configuration.read") && <ConfigurationPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}

      {page === "networks" && <NetworkPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey}
        onReferenceRefresh={async () => { await loadReferenceData(token, currentUser.permissions); if (currentUser.permissions.includes("geo.read")) await references.loadCrossNetworkGeography(); }} />}

      {page === "groups" && <GroupPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} onGroupsRefresh={references.loadGroups} />}

      {page === "customers" && <CustomerPage token={token} customers={customers.customers} total={customers.total} page={customers.page} setPage={customers.setPage}
        pageSize={customers.pageSize} setPageSize={customers.setPageSize} search={customers.search} setSearch={customers.setSearch}
        customerNameFilter={customers.customerNameFilter} setCustomerNameFilter={customers.setCustomerNameFilter}
        customerServiceFilter={customers.customerServiceFilter} setCustomerServiceFilter={customers.setCustomerServiceFilter}
        customerSectorFilter={customers.customerSectorFilter} setCustomerSectorFilter={customers.setCustomerSectorFilter}
        customerServiceVlanFilter={customers.customerServiceVlanFilter} setCustomerServiceVlanFilter={customers.setCustomerServiceVlanFilter}
        customerCustomerVlanFilter={customers.customerCustomerVlanFilter} setCustomerCustomerVlanFilter={customers.setCustomerCustomerVlanFilter}
        sort={customers.sort} setSort={customers.setSort} selected={customers.selected} services={customers.services} form={customers.form} setForm={customers.setForm}
        serviceForm={customers.serviceForm} setServiceForm={customers.setServiceForm} sectors={references.scopeSectors}
        onSelect={(customer: any) => void customers.selectCustomer(customer)} onCreate={customers.createCustomer}
        onStatusChange={(status: string) => void customers.updateCustomerStatus(status)} onCreateService={customers.createService}
        onDelete={customers.deleteSelected} onDeleteService={customers.deleteService} busy={busy} permissions={currentUser.permissions} />}

      {page === "data-reporting" && <DataReportingPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}

      {page === "account" && <AccountPage token={token} user={currentUser} refreshKey={viewRefreshKey} onSignedOut={clearLocalSession} />}
      {page === "recycle" && currentUser.permissions.includes("recycle_bin.read") && <RecycleBinPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}
      {page === "restore-points" && currentUser.permissions.includes("restore_points.read") && <RestorePointsPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}
      {page === "logs" && (currentUser.permissions.includes("audit.read") || currentUser.permissions.includes("logs.read")) && <LogsPage token={token} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}
      {page === "users" && currentUser.permissions.includes("user.read") && <UserManagementPage token={token} busy={busy} permissions={currentUser.permissions} refreshKey={viewRefreshKey} />}
      {page === "settings" && currentUser.permissions.includes("settings.read") && <SettingsPage token={token} canManage={currentUser.permissions.includes("settings.manage")} refreshKey={viewRefreshKey} />}

      {page === "topology" && <TopologyPage token={token} refreshKey={viewRefreshKey} permissions={currentUser.permissions}
        sourceNetworks={references.topologySourceNetworks} networks={references.scopeNetworks} cities={references.scopeCities}
        locations={references.scopeLocations} sectors={references.scopeSectors} groups={references.groups} topology={topology.topology}
        onLoad={topology.loadNetwork} onLoadGroup={topology.loadGroup} onTestAccessibility={devices.testAccessibility} onDeleteDevice={topology.deleteDevice} />}
    </AppShell>
    <SessionExpiryDialog
      offer={sessionExtensionOffer}
      busy={sessionExtensionBusy}
      onExtend={() => void extendCurrentSession().catch((err) => handleError(err, "Unable to extend the session."))}
      onDecline={declineSessionExtension}
    />
    </>
  );
}
