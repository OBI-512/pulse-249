export type ConfigurationVersion = {
  id: string;
  template_id: string;
  version_number: number;
  status: string;
  adapter_key: string;
  transport: string;
  capabilities: string[];
  parameter_schema: Record<string, unknown>;
  transport_parameters: Record<string, unknown>;
  source_version_id: string | null;
  tested_definition_sha256: string | null;
  tested_at: string | null;
  tested_by_user_id: string | null;
  approved_at: string | null;
  approved_by_user_id: string | null;
  content_sha256: string | null;
  published_at: string | null;
  published_by_user_id: string | null;
  change_note: string | null;
  created_at: string;
  updated_at: string;
};

export type ConfigurationFunction = {
  id: string;
  template_version_id: string;
  code: string;
  name: string;
  category: string;
  description: string | null;
  parameter_schema: Record<string, unknown>;
  execution_spec: Record<string, unknown>;
  verification_spec: Record<string, unknown>;
  rollback_spec: Record<string, unknown>;
  required_capabilities: string[];
  default_order: number;
  enabled: boolean;
  is_destructive: boolean;
};

export type ConfigurationVersionEntry = { version: ConfigurationVersion; functions: ConfigurationFunction[] };

export type ConfigurationTemplateDetail = {
  template: {
    id: string;
    code: string;
    name: string;
    vendor: string;
    model: string | null;
    series: string | null;
    device_type_id: string;
    is_active: boolean;
    description: string | null;
    created_at: string;
    updated_at: string;
  };
  versions: ConfigurationVersionEntry[];
};

export type ConfigurationSnapshot = {
  id: string;
  device_id: string;
  template_version_id: string | null;
  snapshot_kind: string;
  adapter_key: string;
  artifact_status: string;
  artifact_sha256: string | null;
  plaintext_sha256: string | null;
  normalized_sha256: string | null;
  artifact_size_bytes: number | null;
  is_restorable: boolean;
  created_at: string;
};

export type ParameterDefinition = {
  name: string;
  label?: string;
  value_type?: string;
  required?: boolean;
  sensitive?: boolean;
  default?: unknown;
  description?: string | null;
  choices?: string[];
};

export function publishedVersions(detail: ConfigurationTemplateDetail | null | undefined) {
  return (detail?.versions || [])
    .filter((entry) => entry.version.status === "PUBLISHED")
    .sort((a, b) => b.version.version_number - a.version.version_number);
}

export function sortedVersions(detail: ConfigurationTemplateDetail | null | undefined) {
  return [...(detail?.versions || [])].sort((a, b) => b.version.version_number - a.version.version_number);
}

export function findVersionEntry(catalog: ConfigurationTemplateDetail[], versionId: string | null | undefined) {
  if (!versionId) return null;
  for (const detail of catalog) {
    const found = detail.versions.find((entry) => entry.version.id === versionId);
    if (found) return { detail, entry: found };
  }
  return null;
}

export function configurationDefinition(entry: ConfigurationVersionEntry) {
  const versionParameters = (entry.version.parameter_schema as { parameters?: unknown } | undefined)?.parameters;
  return {
    adapter_key: entry.version.adapter_key,
    transport: entry.version.transport,
    capabilities: entry.version.capabilities,
    parameters: Array.isArray(versionParameters) ? versionParameters : [],
    transport_parameters: entry.version.transport_parameters || {},
    functions: entry.functions.map((fn) => {
      const functionParameters = (fn.parameter_schema as { parameters?: unknown } | undefined)?.parameters;
      return {
        code: fn.code,
        name: fn.name,
        category: fn.category,
        description: fn.description,
        parameters: Array.isArray(functionParameters) ? functionParameters : [],
        execution_spec: fn.execution_spec || {},
        verification_spec: fn.verification_spec || {},
        rollback_spec: fn.rollback_spec || {},
        required_capabilities: fn.required_capabilities || [],
        default_order: fn.default_order,
        enabled: fn.enabled,
        is_destructive: fn.is_destructive,
      };
    }),
  };
}

export function canRestoreSnapshot(snapshot: ConfigurationSnapshot, boundVersionId: string | null | undefined) {
  return Boolean(
    boundVersionId &&
    snapshot.artifact_status === "READY" &&
    snapshot.is_restorable &&
    snapshot.template_version_id === boundVersionId,
  );
}

export function isActiveConfigurationOperation(status: string) {
  return ["QUEUED", "RUNNING", "ROLLING_BACK"].includes(status);
}

export function parameterDefinitions(fn: ConfigurationFunction | null | undefined): ParameterDefinition[] {
  const schema = fn?.parameter_schema as { parameters?: unknown } | undefined;
  return Array.isArray(schema?.parameters) ? schema.parameters as ParameterDefinition[] : [];
}

export function coerceParameterValue(definition: ParameterDefinition, raw: string) {
  const kind = String(definition.value_type || "STRING").toUpperCase();
  if (kind === "INTEGER" || kind === "VLAN_ID") {
    const value = Number.parseInt(raw, 10);
    if (!Number.isFinite(value)) throw new Error(`${definition.label || definition.name} must be an integer.`);
    return value;
  }
  if (kind === "NUMBER") {
    const value = Number(raw);
    if (!Number.isFinite(value)) throw new Error(`${definition.label || definition.name} must be a number.`);
    return value;
  }
  if (kind === "BOOLEAN") return raw === "true";
  return raw;
}
