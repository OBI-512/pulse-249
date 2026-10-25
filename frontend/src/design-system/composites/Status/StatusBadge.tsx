/**
 * Canonical status/state badge for domain values.
 * Legacy semantic classes are intentionally preserved until CP4 style retirement.
 */
export function StatusBadge({ value }: { value: string }) {
  return <span className={`badge badge-${value.toLowerCase()}`}>{value}</span>;
}
