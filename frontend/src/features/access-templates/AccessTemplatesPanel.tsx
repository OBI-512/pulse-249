import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useFeedback } from "../../components/common/FeedbackSystem";
import { DataTable } from "../../design-system/data/DataTable";
import { TableExportButton } from "../../design-system/data/TableExport";
import { ClearFiltersButton } from "../../design-system/composites/FilterBar";
import { Button, Checkbox, Input, Select, Textarea } from "../../design-system/primitives";
import type { City, Device, Group, Location, Network, PageResult, Sector } from "../../types";
import { friendlyError } from "../../utils/feedback";

type Protocol = "SNMP" | "SSH" | "TELNET" | "WEB";
type Visibility = "PRIVATE" | "SHARED";
type SecretProvider = "ENCRYPTED_DATABASE" | "ENV_REFERENCE";
type ScopeType = "DEVICE" | "DEVICE_GROUP" | "LOGICAL_SECTOR" | "LOCATION" | "NETWORK" | "CITY";
type WebCredentialMode = "USERNAME_PASSWORD" | "PASSWORD_ONLY";
type LifecycleStatus = "DRAFT" | "TESTED" | "APPROVED" | "ACTIVE" | "RETIRED";

type AccessTemplate = {
  id: string;
  name: string;
  description: string | null;
  protocol: Protocol;
  protocol_variant: string | null;
  visibility: Visibility;
  owner_user_id: string;
  is_active: boolean;
  settings: Record<string, unknown>;
  secret_providers: Record<string, SecretProvider>;
  created_at: string;
  updated_at: string;
};

type AccessTemplateRevision = {
  id: string;
  template_id: string;
  revision_number: number;
  lifecycle_status: LifecycleStatus;
  protocol_variant: string | null;
  settings: Record<string, unknown>;
  source_revision_id: string | null;
  change_note: string | null;
  definition_sha256: string | null;
  legacy_backfill: boolean;
  secret_providers: Record<string, SecretProvider>;
  tested_at: string | null;
  tested_by_user_id: string | null;
  approved_at: string | null;
  approved_by_user_id: string | null;
  activated_at: string | null;
  activated_by_user_id: string | null;
  retired_at: string | null;
  created_at: string;
  updated_at: string;
};

type LifecycleCreateRead = {
  template_id: string;
  revision: AccessTemplateRevision;
};

type Assignment = {
  id: string;
  template_id: string;
  scope_type: ScopeType;
  scope_id: string;
  priority: number;
  enabled: boolean;
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string;
};

type RevisionTestResult = {
  id: string;
  template_id: string;
  revision_id: string;
  device_id: string;
  status: "SUCCESS" | "FAILED";
  failure_code: string | null;
  sanitized_message: string | null;
  latency_ms: number | null;
  tested_at: string;
  tested_by_user_id: string | null;
};

type SSHHostKeyAction = {
  action: "DISCOVER_HOST_KEY";
  device_id: string;
  template_id: string;
  template_name: string;
  fingerprint: string;
  key_type: string;
  port: number;
  compatibility_profile: string;
  pinned_fingerprint: string | null;
  trust_state: "NEW" | "MATCH" | "MISMATCH";
};

type GeographyOptions = { networks: Network[]; cities: City[]; locations: Location[]; sectors: Sector[] };

type TemplateDraft = {
  name: string;
  description: string;
  protocol: Protocol;
  protocol_variant: string;
  visibility: Visibility;
  port: string;
  timeout_seconds: string;
  retries: string;
  access_mode: "RO" | "RW";
  security_level: "noAuthNoPriv" | "authNoPriv" | "authPriv";
  auth_protocol: string;
  privacy_protocol: string;
  context_name: string;
  compatibility_profile: "MODERN" | "LEGACY_SSH_RSA_DH1_CBC";
  web_credential_mode: WebCredentialMode;
  web_login_page_path: string;
  web_login_submit_path: string;
  web_username_field: string;
  web_password_field: string;
  web_success_path_prefix: string;
  web_success_text: string;
  web_failure_text: string;
  web_capture_hidden_fields: boolean;
};

type SecretDraft = {
  provider: SecretProvider;
  value: string;
  configured: boolean;
  remove: boolean;
};

type SecretField = { key: string; label: string; multiline?: boolean; help?: string };

const EMPTY_GEO: GeographyOptions = { networks: [], cities: [], locations: [], sectors: [] };
const SCOPE_TYPES: ScopeType[] = ["DEVICE", "DEVICE_GROUP", "LOGICAL_SECTOR", "LOCATION", "NETWORK", "CITY"];
const LIFECYCLE_ORDER: LifecycleStatus[] = ["DRAFT", "TESTED", "APPROVED", "ACTIVE", "RETIRED"];

function numberSetting(settings: Record<string, unknown>, key: string, fallback: number): string {
  const value = Number(settings[key]);
  return Number.isFinite(value) ? String(value) : String(fallback);
}

function textSetting(settings: Record<string, unknown>, key: string, fallback: string): string {
  const value = settings[key];
  return typeof value === "string" && value ? value : fallback;
}

function when(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function defaultDraft(protocol: Protocol = "SSH"): TemplateDraft {
  return {
    name: "",
    description: "",
    protocol,
    protocol_variant: protocol === "SNMP" ? "V2C" : protocol === "TELNET" ? "PASSWORD" : protocol === "WEB" ? "FORM_POST" : "PASSWORD_OR_KEY",
    visibility: "PRIVATE",
    port: protocol === "SNMP" ? "161" : protocol === "TELNET" ? "23" : protocol === "WEB" ? "443" : "22",
    timeout_seconds: "10",
    retries: "1",
    access_mode: "RO",
    security_level: "noAuthNoPriv",
    auth_protocol: "SHA",
    privacy_protocol: "AES",
    context_name: "",
    compatibility_profile: "MODERN",
    web_credential_mode: "USERNAME_PASSWORD",
    web_login_page_path: "/",
    web_login_submit_path: "/",
    web_username_field: "username",
    web_password_field: "password",
    web_success_path_prefix: "",
    web_success_text: "",
    web_failure_text: "",
    web_capture_hidden_fields: true,
  };
}

function draftFromRevision(template: AccessTemplate, revision: AccessTemplateRevision): TemplateDraft {
  const settings = revision.settings || {};
  const draft = defaultDraft(template.protocol);
  const credentialMode = textSetting(settings, "credential_mode", "USERNAME_PASSWORD") === "PASSWORD_ONLY"
    ? "PASSWORD_ONLY"
    : "USERNAME_PASSWORD";
  return {
    ...draft,
    name: template.name,
    description: template.description || "",
    protocol_variant: revision.protocol_variant || draft.protocol_variant,
    visibility: template.visibility,
    port: numberSetting(settings, "port", Number(draft.port)),
    timeout_seconds: numberSetting(settings, "timeout_seconds", 10),
    retries: numberSetting(settings, "retries", 1),
    access_mode: textSetting(settings, "access_mode", "RO") === "RW" ? "RW" : "RO",
    security_level: (["noAuthNoPriv", "authNoPriv", "authPriv"].includes(textSetting(settings, "security_level", "noAuthNoPriv"))
      ? textSetting(settings, "security_level", "noAuthNoPriv")
      : "noAuthNoPriv") as TemplateDraft["security_level"],
    auth_protocol: textSetting(settings, "auth_protocol", "SHA"),
    privacy_protocol: textSetting(settings, "privacy_protocol", "AES"),
    context_name: textSetting(settings, "context_name", ""),
    compatibility_profile: textSetting(settings, "compatibility_profile", "MODERN") === "LEGACY_SSH_RSA_DH1_CBC"
      ? "LEGACY_SSH_RSA_DH1_CBC"
      : "MODERN",
    web_credential_mode: credentialMode,
    web_login_page_path: textSetting(settings, "login_page_path", "/"),
    web_login_submit_path: textSetting(settings, "login_submit_path", "/"),
    web_username_field: textSetting(settings, "username_field", "username"),
    web_password_field: textSetting(settings, "password_field", "password"),
    web_success_path_prefix: textSetting(settings, "success_path_prefix", ""),
    web_success_text: textSetting(settings, "success_text", ""),
    web_failure_text: textSetting(settings, "failure_text", ""),
    web_capture_hidden_fields: settings.capture_hidden_fields !== false,
  };
}

export function accessTemplateSecretFields(draft: Pick<TemplateDraft, "protocol" | "protocol_variant" | "web_credential_mode">): SecretField[] {
  if (draft.protocol === "SSH") {
    return [
      { key: "username", label: "Username" },
      { key: "password", label: "Password" },
      { key: "private_key", label: "Private key", multiline: true, help: "Alternative to password authentication." },
      { key: "private_key_passphrase", label: "Private-key passphrase", help: "Optional passphrase for an encrypted private key." },
    ];
  }
  if (draft.protocol === "TELNET") {
    return [
      { key: "username", label: "Username" },
      { key: "password", label: "Password" },
    ];
  }
  if (draft.protocol === "WEB") {
    if (draft.protocol_variant === "NONE") return [];
    if (draft.protocol_variant === "FORM_POST" && draft.web_credential_mode === "PASSWORD_ONLY") {
      return [{ key: "password", label: "Web GUI password" }];
    }
    return [
      { key: "username", label: "Web GUI username" },
      { key: "password", label: "Web GUI password" },
    ];
  }
  if (draft.protocol_variant === "V3") {
    return [
      { key: "security_name", label: "Security name" },
      { key: "auth_secret", label: "Authentication secret", help: "Required for authNoPriv and authPriv." },
      { key: "privacy_secret", label: "Privacy secret", help: "Required for authPriv." },
    ];
  }
  return [{ key: "community", label: "Community" }];
}

export function buildAccessTemplateSettings(draft: TemplateDraft): Record<string, unknown> {
  const settings: Record<string, unknown> = {
    timeout_seconds: Number(draft.timeout_seconds),
  };
  if (draft.protocol !== "WEB") settings.port = Number(draft.port);
  if (draft.protocol === "SNMP") {
    settings.retries = Number(draft.retries);
    settings.access_mode = draft.access_mode;
    if (draft.protocol_variant === "V3") {
      settings.security_level = draft.security_level;
      if (draft.context_name.trim()) settings.context_name = draft.context_name.trim();
      if (draft.security_level !== "noAuthNoPriv") settings.auth_protocol = draft.auth_protocol;
      if (draft.security_level === "authPriv") settings.privacy_protocol = draft.privacy_protocol;
    }
  } else if (draft.protocol === "SSH") {
    settings.compatibility_profile = draft.compatibility_profile;
  } else if (draft.protocol === "WEB" && draft.protocol_variant === "FORM_POST") {
    settings.credential_mode = draft.web_credential_mode;
    settings.login_page_path = draft.web_login_page_path.trim() || "/";
    settings.login_submit_path = draft.web_login_submit_path.trim() || settings.login_page_path;
    if (draft.web_credential_mode === "USERNAME_PASSWORD") {
      settings.username_field = draft.web_username_field.trim() || "username";
    }
    settings.password_field = draft.web_password_field.trim() || "password";
    settings.capture_hidden_fields = draft.web_capture_hidden_fields;
    if (draft.web_success_path_prefix.trim()) settings.success_path_prefix = draft.web_success_path_prefix.trim();
    if (draft.web_success_text.trim()) settings.success_text = draft.web_success_text.trim();
    if (draft.web_failure_text.trim()) settings.failure_text = draft.web_failure_text.trim();
  }
  return settings;
}

async function fetchAllDevices(token: string): Promise<Device[]> {
  const items: Device[] = [];
  const pageSize = 500;
  let page = 1;
  while (true) {
    const result = await apiFetch<PageResult<Device>>(
      `/devices/inventory/page?page=${page}&page_size=${pageSize}&sort_by=display_name&sort_direction=asc`, {}, token,
    );
    items.push(...(result.items || []));
    if (items.length >= result.total || result.items.length < pageSize) return items;
    page += 1;
  }
}

function scopeLabel(scope: ScopeType): string {
  return {
    DEVICE: "Device",
    DEVICE_GROUP: "Device group",
    LOGICAL_SECTOR: "Logical sector",
    LOCATION: "Location",
    NETWORK: "Network",
    CITY: "City",
  }[scope];
}

function optionLabel(item: { name?: string; display_name?: string; code?: string | null; management_ip?: string | null }): string {
  const name = item.display_name || item.name || "Unnamed";
  const suffix = item.management_ip || item.code;
  return suffix ? `${name} (${suffix})` : name;
}

function statusLabel(status: LifecycleStatus): string {
  return status.charAt(0) + status.slice(1).toLowerCase();
}

function lifecycleRank(status: LifecycleStatus): number {
  return LIFECYCLE_ORDER.indexOf(status);
}

export function AccessTemplatesPanel({
  token,
  permissions,
  currentUserId,
  refreshKey = 0,
}: {
  token: string;
  permissions: string[];
  currentUserId: string;
  refreshKey?: number;
}) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const canManage = permissions.includes("access_template.manage");
  const canTest = permissions.includes("access_template.test");

  const [templates, setTemplates] = useState<AccessTemplate[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revisions, setRevisions] = useState<AccessTemplateRevision[]>([]);
  const [selectedRevisionId, setSelectedRevisionId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState<TemplateDraft>(() => defaultDraft());
  const [secretDrafts, setSecretDrafts] = useState<Record<string, SecretDraft>>({});
  const [changeNote, setChangeNote] = useState("");
  const [familyName, setFamilyName] = useState("");
  const [familyDescription, setFamilyDescription] = useState("");
  const [familyVisibility, setFamilyVisibility] = useState<Visibility>("PRIVATE");
  const [cloneName, setCloneName] = useState("");
  const [cloneDescription, setCloneDescription] = useState("");
  const [cloneVisibility, setCloneVisibility] = useState<Visibility>("PRIVATE");

  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [geography, setGeography] = useState<GeographyOptions>(EMPTY_GEO);
  const [groups, setGroups] = useState<Group[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [scopeType, setScopeType] = useState<ScopeType>("DEVICE");
  const [scopeId, setScopeId] = useState("");
  const [priority, setPriority] = useState("0");
  const [assignmentEnabled, setAssignmentEnabled] = useState(true);
  const [testDeviceId, setTestDeviceId] = useState("");
  const [testResult, setTestResult] = useState<RevisionTestResult | null>(null);

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [busy, setBusy] = useState(false);

  const loadTemplates = useCallback(async () => {
    const rows = await apiFetch<AccessTemplate[]>("/access-templates?include_inactive=true", {}, token);
    setTemplates(rows);
  }, [token]);

  const loadTargets = useCallback(async () => {
    const [geoResult, groupResult, deviceResult] = await Promise.allSettled([
      permissions.includes("geo.read")
        ? apiFetch<GeographyOptions>("/geography/scope-options", {}, token)
        : Promise.resolve(EMPTY_GEO),
      permissions.includes("group.read")
        ? apiFetch<Group[]>("/device-groups", {}, token)
        : Promise.resolve([] as Group[]),
      permissions.includes("device.read")
        ? fetchAllDevices(token)
        : Promise.resolve([] as Device[]),
    ]);
    setGeography(geoResult.status === "fulfilled" ? geoResult.value : EMPTY_GEO);
    setGroups(groupResult.status === "fulfilled" ? groupResult.value : []);
    setDevices(deviceResult.status === "fulfilled" ? deviceResult.value : []);
  }, [permissions, token]);

  const selected = useMemo(() => templates.find((item) => item.id === selectedId) || null, [templates, selectedId]);
  const selectedRevision = useMemo(
    () => revisions.find((item) => item.id === selectedRevisionId) || null,
    [revisions, selectedRevisionId],
  );
  const selectedOwned = Boolean(selected && selected.owner_user_id === currentUserId);
  const definitionEditable = Boolean(creating || (selectedOwned && selectedRevision?.lifecycle_status === "DRAFT"));

  useEffect(() => {
    void loadTemplates().catch((error) => feedback.error(friendlyError(error, "Unable to load Access Templates.")));
    void loadTargets().catch(() => undefined);
  }, [loadTemplates, loadTargets, refreshKey, feedback]);

  useEffect(() => {
    if (!creating && !selectedId && templates.length) setSelectedId(templates[0].id);
    if (selectedId && !templates.some((item) => item.id === selectedId)) setSelectedId(templates[0]?.id || null);
  }, [creating, selectedId, templates]);

  useEffect(() => {
    if (!selected || creating) return;
    setFamilyName(selected.name);
    setFamilyDescription(selected.description || "");
    setFamilyVisibility(selected.visibility);
  }, [selected, creating]);

  useEffect(() => {
    if (creating || !selected) {
      setRevisions([]);
      setSelectedRevisionId(null);
      setAssignments([]);
      return;
    }
    let cancelled = false;
    void Promise.all([
      apiFetch<AccessTemplateRevision[]>(`/access-templates/${selected.id}/revisions`, {}, token),
      apiFetch<Assignment[]>(`/access-templates/${selected.id}/assignments`, {}, token).catch(() => [] as Assignment[]),
    ]).then(([revisionRows, assignmentRows]) => {
      if (cancelled) return;
      setRevisions(revisionRows);
      setAssignments(assignmentRows);
      setSelectedRevisionId((current) => revisionRows.some((item) => item.id === current) ? current : revisionRows[0]?.id || null);
      setCloneName(`${selected.name} Copy`);
      setCloneDescription(selected.description || "");
      setCloneVisibility(selected.visibility);
    }).catch((error) => {
      if (!cancelled) feedback.error(friendlyError(error, "Unable to load Access Template lifecycle history."));
    });
    return () => { cancelled = true; };
  }, [creating, selected, token, feedback]);

  useEffect(() => {
    if (creating || !selected || !selectedRevision) return;
    const next = draftFromRevision(selected, selectedRevision);
    setDraft(next);
    setSecretDrafts(Object.fromEntries(accessTemplateSecretFields(next).map((field) => [field.key, {
      provider: (selectedRevision.secret_providers[field.key] || "ENCRYPTED_DATABASE") as SecretProvider,
      value: "",
      configured: Boolean(selectedRevision.secret_providers[field.key]),
      remove: false,
    }])));
    setChangeNote(selectedRevision.change_note || "");
    setTestResult(null);
  }, [creating, selected, selectedRevision]);

  useEffect(() => {
    setScopeId("");
  }, [scopeType]);

  const displayedTemplates = useMemo(() => {
    const query = search.trim().toLowerCase();
    return templates.filter((item) =>
      (!protocolFilter || item.protocol === protocolFilter)
      && (!query || `${item.name} ${item.description || ""} ${item.protocol} ${item.protocol_variant || ""}`.toLowerCase().includes(query)),
    );
  }, [templates, search, protocolFilter]);

  const revisionNumberById = useMemo(
    () => new Map(revisions.map((item) => [item.id, item.revision_number])),
    [revisions],
  );

  const activeRevision = useMemo(
    () => revisions.find((item) => item.lifecycle_status === "ACTIVE") || null,
    [revisions],
  );

  const targetOptions = useMemo(() => {
    if (scopeType === "DEVICE") return devices.map((item) => ({ id: item.id, label: optionLabel(item) }));
    if (scopeType === "DEVICE_GROUP") return groups.map((item) => ({ id: item.id, label: optionLabel(item) }));
    if (scopeType === "LOGICAL_SECTOR") return geography.sectors.map((item) => ({ id: item.id, label: optionLabel(item) }));
    if (scopeType === "LOCATION") return geography.locations.map((item) => ({ id: item.id, label: optionLabel(item) }));
    if (scopeType === "NETWORK") return geography.networks.map((item) => ({ id: item.id, label: optionLabel(item) }));
    return geography.cities.map((item) => ({ id: item.id, label: optionLabel(item) }));
  }, [scopeType, devices, groups, geography]);

  const targetName = useCallback((assignment: Assignment) => {
    const collections: Record<ScopeType, Array<{ id: string; name?: string; display_name?: string; code?: string | null; management_ip?: string | null }>> = {
      DEVICE: devices,
      DEVICE_GROUP: groups,
      LOGICAL_SECTOR: geography.sectors,
      LOCATION: geography.locations,
      NETWORK: geography.networks,
      CITY: geography.cities,
    };
    const item = collections[assignment.scope_type].find((candidate) => candidate.id === assignment.scope_id);
    return item ? optionLabel(item) : assignment.scope_id;
  }, [devices, groups, geography]);

  const reconcileSecrets = (nextDraft: TemplateDraft) => {
    setSecretDrafts((current) => Object.fromEntries(accessTemplateSecretFields(nextDraft).map((field) => [field.key, current[field.key] || {
      provider: "ENCRYPTED_DATABASE" as SecretProvider,
      value: "",
      configured: false,
      remove: false,
    }])));
  };

  const beginCreate = () => {
    const next = defaultDraft("SSH");
    setCreating(true);
    setSelectedId(null);
    setSelectedRevisionId(null);
    setDraft(next);
    setSecretDrafts(Object.fromEntries(accessTemplateSecretFields(next).map((field) => [field.key, {
      provider: "ENCRYPTED_DATABASE" as SecretProvider,
      value: "",
      configured: false,
      remove: false,
    }])));
    setChangeNote("");
    setAssignments([]);
    setTestResult(null);
  };

  const cancelCreate = () => {
    setCreating(false);
    setSelectedId(templates[0]?.id || null);
  };

  const changeProtocol = (protocol: Protocol) => {
    const next = { ...defaultDraft(protocol), name: draft.name, description: draft.description, visibility: draft.visibility };
    setDraft(next);
    reconcileSecrets(next);
  };

  const changeVariant = (variant: string) => {
    const next = { ...draft, protocol_variant: variant };
    setDraft(next);
    reconcileSecrets(next);
  };

  const changeWebCredentialMode = (mode: WebCredentialMode) => {
    const next = { ...draft, web_credential_mode: mode };
    setDraft(next);
    reconcileSecrets(next);
  };

  const buildSecretsPayload = (isCreate: boolean) => {
    const payload: Record<string, unknown> = {};
    for (const field of accessTemplateSecretFields(draft)) {
      const item = secretDrafts[field.key];
      if (!item) continue;
      if (!isCreate && item.remove) {
        payload[field.key] = null;
        continue;
      }
      if (!item.value.trim()) continue;
      payload[field.key] = item.provider === "ENV_REFERENCE"
        ? { provider: item.provider, reference: item.value.trim() }
        : { provider: item.provider, value: item.value };
    }
    if (
      !isCreate
      && selected?.protocol === "WEB"
      && draft.protocol_variant === "FORM_POST"
      && draft.web_credential_mode === "PASSWORD_ONLY"
      && selectedRevision?.secret_providers.username
    ) {
      payload.username = null;
    }
    return payload;
  };

  const createFamily = async () => {
    if (!canManage || !creating) return;
    if (!draft.name.trim()) {
      feedback.error("Template name is required.");
      return;
    }
    setBusy(true);
    try {
      const result = await apiFetch<LifecycleCreateRead>("/access-templates/families", {
        method: "POST",
        body: JSON.stringify({
          name: draft.name.trim(),
          description: draft.description.trim() || null,
          protocol: draft.protocol,
          protocol_variant: draft.protocol_variant,
          visibility: draft.visibility,
          is_active: false,
          settings: buildAccessTemplateSettings(draft),
          secrets: buildSecretsPayload(true),
          change_note: changeNote.trim() || null,
        }),
      }, token);
      await loadTemplates();
      setCreating(false);
      setSelectedId(result.template_id);
      setSelectedRevisionId(result.revision.id);
      feedback.success("Access Template draft family created. Test, approve, then activate the revision when ready.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to create Access Template lifecycle family."));
    } finally {
      setBusy(false);
    }
  };

  const saveFamilyMetadata = async () => {
    if (!selected || !selectedOwned || !canManage) return;
    if (!familyName.trim()) {
      feedback.error("Family name is required.");
      return;
    }
    setBusy(true);
    try {
      const updated = await apiFetch<AccessTemplate>(`/access-templates/${selected.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: familyName.trim(),
          description: familyDescription.trim(),
          visibility: familyVisibility,
        }),
      }, token);
      setTemplates((current) => current.map((item) => item.id === updated.id ? updated : item));
      feedback.success("Access Template family metadata updated. Revision definition and lifecycle state were not changed.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to update Access Template family metadata."));
    } finally {
      setBusy(false);
    }
  };

  const saveDraftRevision = async () => {
    if (!selected || !selectedRevision || !selectedOwned || !canManage || selectedRevision.lifecycle_status !== "DRAFT") return;
    setBusy(true);
    try {
      const secrets = buildSecretsPayload(false);
      const updated = await apiFetch<AccessTemplateRevision>(`/access-templates/${selected.id}/revisions/${selectedRevision.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          protocol_variant: draft.protocol_variant,
          settings: buildAccessTemplateSettings(draft),
          ...(Object.keys(secrets).length ? { secrets } : {}),
          change_note: changeNote.trim() || null,
        }),
      }, token);
      setRevisions((current) => current.map((item) => item.id === updated.id ? updated : item));
      setSelectedRevisionId(updated.id);
      feedback.success("Draft revision saved. Any prior test evidence for this draft is invalidated by definition changes.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to save Access Template draft revision."));
    } finally {
      setBusy(false);
    }
  };

  const createRevision = async () => {
    if (!selected || !selectedRevision || !selectedOwned || !canManage) return;
    setBusy(true);
    try {
      const created = await apiFetch<AccessTemplateRevision>(`/access-templates/${selected.id}/revisions`, {
        method: "POST",
        body: JSON.stringify({
          source_revision_id: selectedRevision.id,
          change_note: `New revision from revision ${selectedRevision.revision_number}.`,
        }),
      }, token);
      setRevisions((current) => [created, ...current]);
      setSelectedRevisionId(created.id);
      feedback.success(`Revision ${created.revision_number} created as Draft with the selected revision's credentials copied server-side.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to create Access Template revision."));
    } finally {
      setBusy(false);
    }
  };

  const duplicateFamily = async () => {
    if (!selected || !selectedRevision || !canManage) return;
    if (!cloneName.trim()) {
      feedback.error("Duplicate family name is required.");
      return;
    }
    setBusy(true);
    try {
      const result = await apiFetch<LifecycleCreateRead>(`/access-templates/${selected.id}/clone`, {
        method: "POST",
        body: JSON.stringify({
          source_revision_id: selectedRevision.id,
          name: cloneName.trim(),
          description: cloneDescription.trim() || null,
          visibility: cloneVisibility,
          change_note: `Duplicated from ${selected.name} revision ${selectedRevision.revision_number}. Credentials intentionally not copied.`,
        }),
      }, token);
      await loadTemplates();
      setCreating(false);
      setSelectedId(result.template_id);
      setSelectedRevisionId(result.revision.id);
      feedback.success("Access Template family duplicated as a new Draft. Re-enter credentials before testing; credentials are intentionally not copied.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to duplicate Access Template family."));
    } finally {
      setBusy(false);
    }
  };

  const testRevision = async () => {
    if (!selected || !selectedRevision || !canTest || !testDeviceId) return;
    if (!["DRAFT", "TESTED", "ACTIVE"].includes(selectedRevision.lifecycle_status)) {
      feedback.error("Only Draft, Tested, or Active revisions can be tested from this workspace.");
      return;
    }
    setBusy(true);
    setTestResult(null);
    try {
      const endpoint = `/access-templates/${selected.id}/revisions/${selectedRevision.id}/test`;
      let result = await apiFetch<RevisionTestResult | SSHHostKeyAction>(endpoint, {
        method: "POST",
        body: JSON.stringify({ device_id: testDeviceId }),
      }, token);

      if ("action" in result) {
        const device = devices.find((item) => item.id === testDeviceId);
        const deviceLabel = device ? optionLabel(device) : testDeviceId;
        const replacing = result.trust_state === "MISMATCH";
        const message = replacing
          ? `SSH HOST KEY CHANGED for ${deviceLabel}.\n\nTrusted fingerprint:\n${result.pinned_fingerprint || "Not available"}\n\nCurrently observed fingerprint:\n${result.fingerprint}\n\nKey type: ${result.key_type}\nPort: ${result.port}\nCompatibility: ${result.compatibility_profile}\n\nReplace the trusted key only after independently verifying this fingerprint.`
          : `FTTW observed this SSH host key for ${deviceLabel}:\n\n${result.fingerprint}\n\nKey type: ${result.key_type}\nPort: ${result.port}\nCompatibility: ${result.compatibility_profile}\n\nTrust and save this device-specific SSH host key and continue the revision test?`;
        if (!await dialog.confirm({ message })) return;
        const confirmed = await apiFetch<RevisionTestResult | SSHHostKeyAction>(endpoint, {
          method: "POST",
          body: JSON.stringify({
            device_id: testDeviceId,
            trust_host_key: true,
            expected_fingerprint: result.fingerprint,
            replace_existing: replacing,
          }),
        }, token);
        if ("action" in confirmed) throw new Error("SSH host-key confirmation did not complete.");
        result = confirmed;
      }

      setTestResult(result);
      const refreshed = await apiFetch<AccessTemplateRevision[]>(`/access-templates/${selected.id}/revisions`, {}, token);
      setRevisions(refreshed);
      setSelectedRevisionId(selectedRevision.id);
      if (result.status === "SUCCESS") feedback.success("Revision connection test succeeded.");
      else feedback.error(result.sanitized_message || result.failure_code || "Revision connection test failed.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to test Access Template revision."));
    } finally {
      setBusy(false);
    }
  };

  const approveRevision = async () => {
    if (!selected || !selectedRevision || !selectedOwned || !canManage || selectedRevision.lifecycle_status !== "TESTED") return;
    setBusy(true);
    try {
      const approved = await apiFetch<AccessTemplateRevision>(`/access-templates/${selected.id}/revisions/${selectedRevision.id}/approve`, {
        method: "POST",
      }, token);
      setRevisions((current) => current.map((item) => item.id === approved.id ? approved : item));
      setSelectedRevisionId(approved.id);
      feedback.success(`Revision ${approved.revision_number} approved.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to approve Access Template revision."));
    } finally {
      setBusy(false);
    }
  };

  const activateRevision = async () => {
    if (!selected || !selectedRevision || !selectedOwned || !canManage || selectedRevision.lifecycle_status !== "APPROVED") return;
    if (!await dialog.confirm({ message: `Activate revision ${selectedRevision.revision_number} of ${selected.name}? The currently Active revision, if any, will become Retired.` })) return;
    setBusy(true);
    try {
      const activated = await apiFetch<AccessTemplateRevision>(`/access-templates/${selected.id}/revisions/${selectedRevision.id}/activate`, {
        method: "POST",
      }, token);
      const [templateRows, revisionRows] = await Promise.all([
        apiFetch<AccessTemplate[]>("/access-templates?include_inactive=true", {}, token),
        apiFetch<AccessTemplateRevision[]>(`/access-templates/${selected.id}/revisions`, {}, token),
      ]);
      setTemplates(templateRows);
      setRevisions(revisionRows);
      setSelectedRevisionId(activated.id);
      feedback.success(`Revision ${activated.revision_number} is now Active. Any previous Active revision is Retired.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to activate Access Template revision."));
    } finally {
      setBusy(false);
    }
  };

  const createAssignment = async () => {
    if (!selected || !selected.is_active || !canManage || !scopeId) return;
    setBusy(true);
    try {
      await apiFetch(`/access-templates/${selected.id}/assignments`, {
        method: "POST",
        body: JSON.stringify({ scope_type: scopeType, scope_id: scopeId, priority: Number(priority || 0), enabled: assignmentEnabled }),
      }, token);
      const rows = await apiFetch<Assignment[]>(`/access-templates/${selected.id}/assignments`, {}, token);
      setAssignments(rows);
      setScopeId("");
      feedback.success("Access Template assignment created.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to create Access Template assignment."));
    } finally {
      setBusy(false);
    }
  };

  const removeAssignment = async (assignment: Assignment) => {
    if (!selected || !canManage) return;
    if (!await dialog.confirm({ message: `Remove this ${scopeLabel(assignment.scope_type).toLowerCase()} assignment?` })) return;
    setBusy(true);
    try {
      await apiFetch(`/access-templates/${selected.id}/assignments/${assignment.id}`, { method: "DELETE" }, token);
      const rows = await apiFetch<Assignment[]>(`/access-templates/${selected.id}/assignments`, {}, token);
      setAssignments(rows);
      feedback.success("Access Template assignment removed.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to remove the direct Access Template assignment."));
    } finally {
      setBusy(false);
    }
  };

  const secretFields = accessTemplateSecretFields(draft);
  const selectedTestable = Boolean(selectedRevision && ["DRAFT", "TESTED", "ACTIVE"].includes(selectedRevision.lifecycle_status));

  return <div className="settings-access-templates">
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>Access Templates</h3>
          <span>Lifecycle-managed reusable access definitions. Draft → Tested → Approved → Active; superseded Active revisions become Retired.</span>
        </div>
        {canManage && <Button unstyled onClick={beginCreate} disabled={busy}>New Access Template</Button>}
      </div>
      <div className="filter-row compact management-filter-row">
        <Input unstyled value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search templates..." />
        <Select unstyled value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
          <option value="">All protocols</option><option>SNMP</option><option>SSH</option><option>TELNET</option><option>WEB</option>
        </Select>
        <TableExportButton token={token} tableId="access_templates" filters={{ search, protocol: protocolFilter, include_inactive: true }} />
        <ClearFiltersButton disabled={!search && !protocolFilter} onClick={() => { setSearch(""); setProtocolFilter(""); }} />
      </div>
      <DataTable viewportClassName="table-wrap" className="clickable-table">
        <thead><tr><th>Name</th><th>Protocol</th><th>Visibility</th><th>Family state</th><th>Owner</th></tr></thead>
        <tbody>{displayedTemplates.map((item) => <tr key={item.id} className={selectedId === item.id ? "selected-row" : ""} onClick={() => { setCreating(false); setSelectedId(item.id); setSelectedRevisionId(null); }}>
          <td><strong>{item.name}</strong>{item.description ? <div className="muted">{item.description}</div> : null}</td>
          <td>{item.protocol}{item.protocol_variant ? ` / ${item.protocol_variant}` : ""}{item.protocol === "TELNET" ? <div className="muted">Legacy plaintext transport</div> : item.protocol === "WEB" ? <div className="muted">Gateway-side device authentication</div> : null}</td>
          <td>{item.visibility === "SHARED" ? "Shared" : "Private"}</td>
          <td>{item.is_active ? "Active projection" : "Inactive family"}</td>
          <td>{item.owner_user_id === currentUserId ? "You" : "Shared by another user"}</td>
        </tr>)}</tbody>
      </DataTable>
      {!displayedTemplates.length && <div className="empty-cell">No Access Templates found.</div>}
    </section>

    {creating && <section className="panel">
      <div className="panel-header"><div><h3>Create Access Template</h3><span>Creates an inactive family with revision 1 in Draft state. Activation is never automatic.</span></div></div>
      <div className="form-grid three">
        <label>Name<Input unstyled value={draft.name} disabled={busy} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label>
        <label>Protocol<Select unstyled value={draft.protocol} disabled={busy} onChange={(event) => changeProtocol(event.target.value as Protocol)}><option>SSH</option><option>SNMP</option><option>TELNET</option><option>WEB</option></Select></label>
        <label>Visibility<Select unstyled value={draft.visibility} disabled={busy} onChange={(event) => setDraft({ ...draft, visibility: event.target.value as Visibility })}><option value="PRIVATE">Private</option><option value="SHARED">Shared</option></Select></label>
      </div>
      <label>Description<Textarea unstyled rows={2} value={draft.description} disabled={busy} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label>
      <DefinitionEditor draft={draft} disabled={busy} onDraft={setDraft} onVariant={changeVariant} onWebCredentialMode={changeWebCredentialMode} />
      <SecretsEditor fields={secretFields} drafts={secretDrafts} editable={!busy} onChange={setSecretDrafts} />
      <label>Change note<Textarea unstyled rows={2} value={changeNote} disabled={busy} placeholder="Why is this Access Template being created?" onChange={(event) => setChangeNote(event.target.value)} /></label>
      <div className="inline-status-message">Lifecycle start state: Draft. The family remains inactive until a successfully Tested revision is Approved and explicitly Activated.</div>
      <div className="button-row"><Button unstyled onClick={() => void createFamily()} disabled={busy}>Create Draft family</Button><Button unstyled className="secondary" onClick={cancelCreate} disabled={busy}>Cancel</Button></div>
    </section>}

    {selected && !creating && <>
      <section className="panel">
        <div className="panel-header">
          <div><h3>{selected.name}</h3><span>{selectedOwned ? "Owned by you" : "Shared with you — lifecycle history is readable; owner-only mutation remains blocked by the API."}</span></div>
          <div className="button-row">
            {selectedOwned && canManage && <Button unstyled className="secondary" onClick={() => void saveFamilyMetadata()} disabled={busy || !familyName.trim()}>Save family metadata</Button>}
            {selectedOwned && canManage && selectedRevision && <Button unstyled className="secondary" onClick={() => void createRevision()} disabled={busy}>New revision from selected</Button>}
          </div>
        </div>
        <div className="form-grid three">
          <label>Family name<Input unstyled value={familyName} disabled={!selectedOwned || !canManage || busy} onChange={(event) => setFamilyName(event.target.value)} /></label>
          <label>Protocol<Input unstyled value={selected.protocol} disabled /></label>
          <label>Visibility<Select unstyled value={familyVisibility} disabled={!selectedOwned || !canManage || busy} onChange={(event) => setFamilyVisibility(event.target.value as Visibility)}><option value="PRIVATE">Private</option><option value="SHARED">Shared</option></Select></label>
        </div>
        <label>Description<Textarea unstyled rows={2} value={familyDescription} disabled={!selectedOwned || !canManage || busy} onChange={(event) => setFamilyDescription(event.target.value)} /></label>
        <div className="inline-status-message">Family projection: {selected.is_active ? `Active${activeRevision ? ` on revision ${activeRevision.revision_number}` : ""}.` : "Inactive."} Family metadata may change independently; protocol settings, credentials, and lifecycle state remain revision-controlled.</div>
      </section>

      <section className="panel">
        <div className="panel-header"><div><h3>Revision history</h3><span>Lineage, lifecycle state, and immutable operational evidence for each version.</span></div></div>
        <DataTable viewportClassName="table-wrap" className="clickable-table">
          <thead><tr><th>Revision</th><th>Status</th><th>Source</th><th>Tested</th><th>Approved</th><th>Activated / retired</th></tr></thead>
          <tbody>{revisions.map((revision) => <tr key={revision.id} className={selectedRevisionId === revision.id ? "selected-row" : ""} onClick={() => setSelectedRevisionId(revision.id)}>
            <td><strong>#{revision.revision_number}</strong>{revision.legacy_backfill ? <div className="muted">Legacy backfill</div> : null}</td>
            <td>{statusLabel(revision.lifecycle_status)}</td>
            <td>{revision.source_revision_id ? `#${revisionNumberById.get(revision.source_revision_id) || "?"}` : "Original"}</td>
            <td>{when(revision.tested_at)}</td>
            <td>{when(revision.approved_at)}</td>
            <td>{revision.lifecycle_status === "RETIRED" ? `Retired ${when(revision.retired_at)}` : when(revision.activated_at)}</td>
          </tr>)}</tbody>
        </DataTable>
        {!revisions.length && <div className="empty-cell">No lifecycle revisions are available for this family.</div>}
      </section>

      {selectedRevision && <section className="panel">
        <div className="panel-header">
          <div><h3>Revision {selectedRevision.revision_number} — {statusLabel(selectedRevision.lifecycle_status)}</h3><span>{selectedRevision.lifecycle_status === "DRAFT" ? "Draft definition can be edited. Saving definition changes clears stale lifecycle evidence." : "This revision is read-only in the definition editor. Create a new Draft revision to change it."}</span></div>
          <div className="button-row">
            {selectedOwned && canManage && selectedRevision.lifecycle_status === "TESTED" && <Button unstyled onClick={() => void approveRevision()} disabled={busy}>Approve revision</Button>}
            {selectedOwned && canManage && selectedRevision.lifecycle_status === "APPROVED" && <Button unstyled onClick={() => void activateRevision()} disabled={busy}>Activate revision</Button>}
          </div>
        </div>
        <div className="inline-status-message">Lifecycle position {lifecycleRank(selectedRevision.lifecycle_status) + 1} of {LIFECYCLE_ORDER.length}: {LIFECYCLE_ORDER.join(" → ")}</div>
        <DefinitionEditor draft={draft} disabled={!definitionEditable || busy} onDraft={setDraft} onVariant={changeVariant} onWebCredentialMode={changeWebCredentialMode} />
        <SecretsEditor fields={secretFields} drafts={secretDrafts} editable={definitionEditable && !busy} onChange={setSecretDrafts} />
        <label>Change note<Textarea unstyled rows={2} value={changeNote} disabled={!definitionEditable || busy} onChange={(event) => setChangeNote(event.target.value)} /></label>
        <div className="form-grid three">
          <label>Definition fingerprint<Input unstyled value={selectedRevision.definition_sha256 || "Not tested"} disabled /></label>
          <label>Created<Input unstyled value={when(selectedRevision.created_at)} disabled /></label>
          <label>Updated<Input unstyled value={when(selectedRevision.updated_at)} disabled /></label>
        </div>
        {definitionEditable && canManage && <div className="button-row"><Button unstyled onClick={() => void saveDraftRevision()} disabled={busy}>Save Draft revision</Button></div>}
        {selectedRevision.lifecycle_status === "ACTIVE" && <p className="field-help">This is the current runtime projection. It cannot be edited in place. Create a new revision, test it, approve it, and activate it to supersede this version.</p>}
        {selectedRevision.lifecycle_status === "RETIRED" && <p className="field-help">Retired revisions remain visible for auditability and lineage. They cannot be edited or activated directly.</p>}
      </section>}

      {canManage && selectedRevision && <section className="panel">
        <div className="panel-header"><div><h3>Duplicate family</h3><span>Creates a new inactive family with revision 1 in Draft state. Definition is copied from the selected revision; credentials are intentionally not copied.</span></div></div>
        <div className="form-grid three">
          <label>New family name<Input unstyled value={cloneName} disabled={busy} onChange={(event) => setCloneName(event.target.value)} /></label>
          <label>Visibility<Select unstyled value={cloneVisibility} disabled={busy} onChange={(event) => setCloneVisibility(event.target.value as Visibility)}><option value="PRIVATE">Private</option><option value="SHARED">Shared</option></Select></label>
          <label>Source revision<Input unstyled value={`#${selectedRevision.revision_number} / ${selectedRevision.lifecycle_status}`} disabled /></label>
        </div>
        <label>Description<Textarea unstyled rows={2} value={cloneDescription} disabled={busy} onChange={(event) => setCloneDescription(event.target.value)} /></label>
        <Button unstyled className="secondary" onClick={() => void duplicateFamily()} disabled={busy || !cloneName.trim()}>Duplicate as Draft</Button>
      </section>}

      <section className="panel">
        <div className="panel-header"><div><h3>Assignments</h3><span>Resolution precedence: Device → Device group → Logical sector → Location → Network → City. The API accepts new assignments only while the family has an Active revision.</span></div></div>
        {canManage && selected.is_active ? <div className="inline-form">
          <Select unstyled aria-label="Assignment scope" value={scopeType} onChange={(event) => setScopeType(event.target.value as ScopeType)}>{SCOPE_TYPES.map((scope) => <option key={scope} value={scope}>{scopeLabel(scope)}</option>)}</Select>
          <Select unstyled aria-label="Assignment target" value={scopeId} onChange={(event) => setScopeId(event.target.value)}><option value="">Select target...</option>{targetOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</Select>
          <Input unstyled aria-label="Assignment priority" type="number" min="-100000" max="100000" value={priority} onChange={(event) => setPriority(event.target.value)} />
          <label className="check-item"><Checkbox unstyled checked={assignmentEnabled} onChange={(event) => setAssignmentEnabled(event.target.checked)} />Enabled</label>
          <Button unstyled className="secondary" onClick={() => void createAssignment()} disabled={busy || !scopeId}>Assign</Button>
        </div> : canManage ? <p className="field-help">Activate an approved revision before creating a new assignment. Existing historical assignments remain visible below.</p> : null}
        <DataTable viewportClassName="table-wrap"><thead><tr><th>Scope</th><th>Target</th><th>Priority</th><th>Status</th><th>Action</th></tr></thead><tbody>{assignments.map((assignment) => {
          const canRemove = canManage && (selected.owner_user_id === currentUserId || assignment.created_by_user_id === currentUserId);
          return <tr key={assignment.id}><td>{scopeLabel(assignment.scope_type)}</td><td>{targetName(assignment)}</td><td>{assignment.priority}</td><td>{assignment.enabled ? "Enabled" : "Disabled"}</td><td>{canRemove ? <Button unstyled className="small danger" onClick={() => void removeAssignment(assignment)} disabled={busy}>Remove</Button> : "—"}</td></tr>;
        })}</tbody></DataTable>
        {!assignments.length && <div className="empty-cell">This template has no assignments.</div>}
      </section>

      {selectedRevision && canTest && <section className="panel">
        <div className="panel-header"><div><h3>Revision connection test</h3><span>Explicit operator action against one authorized device. The exact revision ID is recorded with the test result. No test runs automatically.</span></div></div>
        <div className="inline-form">
          <Select unstyled aria-label="Test device" value={testDeviceId} onChange={(event) => setTestDeviceId(event.target.value)}><option value="">Select device...</option>{devices.map((device) => <option key={device.id} value={device.id}>{optionLabel(device)}</option>)}</Select>
          <Button unstyled className="secondary" onClick={() => void testRevision()} disabled={busy || !testDeviceId || !selectedTestable}>Test selected revision</Button>
        </div>
        {!selectedTestable && <p className="field-help">Approved revisions must either be activated or superseded with a new Draft; Retired revisions remain historical. Active revisions may be operationally re-tested without changing their lifecycle state.</p>}
        {testResult && <div className="inline-status-message">Revision #{selectedRevision.revision_number} — {testResult.status}{testResult.failure_code ? ` — ${testResult.failure_code}` : ""}{testResult.sanitized_message ? ` — ${testResult.sanitized_message}` : ""}{testResult.latency_ms != null ? ` (${testResult.latency_ms} ms)` : ""}</div>}
      </section>}
    </>}
  </div>;
}

function DefinitionEditor({
  draft,
  disabled,
  onDraft,
  onVariant,
  onWebCredentialMode,
}: {
  draft: TemplateDraft;
  disabled: boolean;
  onDraft: (draft: TemplateDraft) => void;
  onVariant: (variant: string) => void;
  onWebCredentialMode: (mode: WebCredentialMode) => void;
}) {
  return <>
    <div className="form-grid three">
      {draft.protocol === "SNMP" && <label>SNMP version<Select unstyled value={draft.protocol_variant} disabled={disabled} onChange={(event) => onVariant(event.target.value)}><option value="V1">v1</option><option value="V2C">v2c</option><option value="V3">v3</option></Select></label>}
      {draft.protocol === "WEB" && <label>Web authentication<Select unstyled value={draft.protocol_variant} disabled={disabled} onChange={(event) => onVariant(event.target.value)}><option value="FORM_POST">Form login (POST)</option><option value="HTTP_BASIC">HTTP Basic</option><option value="HTTP_DIGEST">HTTP Digest</option><option value="NONE">No device login</option></Select></label>}
      {draft.protocol !== "WEB" && <label>Port<Input unstyled type="number" min="1" max="65535" value={draft.port} disabled={disabled} onChange={(event) => onDraft({ ...draft, port: event.target.value })} /></label>}
      <label>Timeout (seconds)<Input unstyled type="number" min="1" max="300" value={draft.timeout_seconds} disabled={disabled} onChange={(event) => onDraft({ ...draft, timeout_seconds: event.target.value })} /></label>
      {draft.protocol === "SNMP" && <><label>Retries<Input unstyled type="number" min="0" max="10" value={draft.retries} disabled={disabled} onChange={(event) => onDraft({ ...draft, retries: event.target.value })} /></label><label>Access policy<Select unstyled value={draft.access_mode} disabled={disabled} onChange={(event) => onDraft({ ...draft, access_mode: event.target.value as "RO" | "RW" })}><option value="RO">Read only</option><option value="RW">Read / write</option></Select></label></>}
      {draft.protocol === "SSH" && <label>Compatibility<Select unstyled value={draft.compatibility_profile} disabled={disabled} onChange={(event) => onDraft({ ...draft, compatibility_profile: event.target.value as TemplateDraft["compatibility_profile"] })}><option value="MODERN">Modern SSH</option><option value="LEGACY_SSH_RSA_DH1_CBC">Legacy RSA / DH1 / CBC (weak)</option></Select></label>}
    </div>
    {draft.protocol === "SNMP" && draft.protocol_variant === "V3" && <div className="form-grid three">
      <label>Security level<Select unstyled value={draft.security_level} disabled={disabled} onChange={(event) => onDraft({ ...draft, security_level: event.target.value as TemplateDraft["security_level"] })}><option value="noAuthNoPriv">noAuthNoPriv</option><option value="authNoPriv">authNoPriv</option><option value="authPriv">authPriv</option></Select></label>
      {draft.security_level !== "noAuthNoPriv" && <label>Authentication protocol<Select unstyled value={draft.auth_protocol} disabled={disabled} onChange={(event) => onDraft({ ...draft, auth_protocol: event.target.value })}><option>SHA</option><option>SHA-224</option><option>SHA-256</option><option>SHA-384</option><option>SHA-512</option><option>MD5</option></Select></label>}
      {draft.security_level === "authPriv" && <label>Privacy protocol<Select unstyled value={draft.privacy_protocol} disabled={disabled} onChange={(event) => onDraft({ ...draft, privacy_protocol: event.target.value })}><option>AES</option><option>DES</option></Select></label>}
      <label>Context name<Input unstyled value={draft.context_name} disabled={disabled} onChange={(event) => onDraft({ ...draft, context_name: event.target.value })} /></label>
    </div>}
    {draft.protocol === "WEB" && draft.protocol_variant === "FORM_POST" && <>
      <div className="inline-status-message">For normal onboarding, use the Secure Web Template Wizard above. These fields are the advanced revision editor for troubleshooting and exceptional devices.</div>
      <div className="form-grid two">
        <label>Device login credentials<Select unstyled value={draft.web_credential_mode} disabled={disabled} onChange={(event) => onWebCredentialMode(event.target.value as WebCredentialMode)}><option value="USERNAME_PASSWORD">Username + password</option><option value="PASSWORD_ONLY">Password only</option></Select></label>
        <label>Login page path<Input unstyled value={draft.web_login_page_path} disabled={disabled} placeholder="/" onChange={(event) => onDraft({ ...draft, web_login_page_path: event.target.value })} /></label>
        <label>Login submit path<Input unstyled value={draft.web_login_submit_path} disabled={disabled} placeholder="/login" onChange={(event) => onDraft({ ...draft, web_login_submit_path: event.target.value })} /></label>
        {draft.web_credential_mode === "USERNAME_PASSWORD" && <label>Username field<Input unstyled value={draft.web_username_field} disabled={disabled} placeholder="username" onChange={(event) => onDraft({ ...draft, web_username_field: event.target.value })} /></label>}
        <label>Password field<Input unstyled value={draft.web_password_field} disabled={disabled} placeholder="password" onChange={(event) => onDraft({ ...draft, web_password_field: event.target.value })} /></label>
        <label>Success path prefix<Input unstyled value={draft.web_success_path_prefix} disabled={disabled} placeholder="/index" onChange={(event) => onDraft({ ...draft, web_success_path_prefix: event.target.value })} /></label>
        <label>Success text<Input unstyled value={draft.web_success_text} disabled={disabled} onChange={(event) => onDraft({ ...draft, web_success_text: event.target.value })} /></label>
        <label>Failure text<Input unstyled value={draft.web_failure_text} disabled={disabled} onChange={(event) => onDraft({ ...draft, web_failure_text: event.target.value })} /></label>
      </div>
      <label className="check-item"><Checkbox unstyled checked={draft.web_capture_hidden_fields} disabled={disabled} onChange={(event) => onDraft({ ...draft, web_capture_hidden_fields: event.target.checked })} />Preserve hidden login fields such as CSRF tokens</label>
    </>}
    {draft.protocol === "TELNET" && <div className="inline-status-message">Telnet sends credentials and device traffic in plaintext. It is globally disabled by default and should only be enabled for explicitly approved legacy devices.</div>}
    {draft.protocol === "SSH" && <p className="field-help">SSH host-key fingerprints remain device-specific. During the first SSH connection test, FTTW retrieves the device key and asks you to Trust & Save its SHA256 fingerprint before authentication continues.</p>}
    {draft.protocol === "WEB" && <p className="field-help">WEB templates contain reusable device-login behavior and credentials only. HTTP/HTTPS scheme, port, enablement, and TLS/certificate trust remain device-specific Secure Web-GUI settings. Authentication is executed inside the access gateway; credentials are never delivered to the operator browser.</p>}
  </>;
}

function SecretsEditor({
  fields,
  drafts,
  editable,
  onChange,
}: {
  fields: SecretField[];
  drafts: Record<string, SecretDraft>;
  editable: boolean;
  onChange: (drafts: Record<string, SecretDraft>) => void;
}) {
  return <>
    <h4>Credentials</h4>
    {!fields.length && <p className="field-help">This definition deliberately uses no stored device credential.</p>}
    <div className="form-grid three">
      {fields.map((field) => {
        const secret = drafts[field.key] || { provider: "ENCRYPTED_DATABASE" as SecretProvider, value: "", configured: false, remove: false };
        const updateSecret = (changes: Partial<SecretDraft>) => onChange({ ...drafts, [field.key]: { ...secret, ...changes } });
        return <div key={field.key}>
          <label>{field.label}<Select unstyled aria-label={`${field.label} storage`} value={secret.provider} disabled={!editable || secret.remove} onChange={(event) => updateSecret({ provider: event.target.value as SecretProvider, value: "" })}><option value="ENCRYPTED_DATABASE">Encrypted database</option><option value="ENV_REFERENCE">env:// reference</option></Select></label>
          {field.multiline && secret.provider === "ENCRYPTED_DATABASE"
            ? <Textarea unstyled rows={3} aria-label={field.label} value={secret.value} disabled={!editable || secret.remove} placeholder={secret.configured ? "Configured — leave blank to keep" : "Enter secret value"} onChange={(event) => updateSecret({ value: event.target.value })} />
            : <Input unstyled type={secret.provider === "ENCRYPTED_DATABASE" ? "password" : "text"} aria-label={field.label} value={secret.value} disabled={!editable || secret.remove} placeholder={secret.configured ? `${secret.provider === "ENV_REFERENCE" ? "env:// reference" : "Secret"} configured — leave blank to keep` : secret.provider === "ENV_REFERENCE" ? "env://VARIABLE_NAME" : "Enter secret value"} onChange={(event) => updateSecret({ value: event.target.value })} />}
          {field.help ? <div className="muted">{field.help}</div> : null}
          {secret.configured && editable ? <label className="check-item"><Checkbox unstyled checked={secret.remove} onChange={(event) => updateSecret({ remove: event.target.checked, value: "" })} />Remove stored credential from this Draft</label> : null}
        </div>;
      })}
    </div>
  </>;
}
