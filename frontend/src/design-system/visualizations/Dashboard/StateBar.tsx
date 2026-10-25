import type { DashboardBreakdown } from "../../../types";
export function AvailabilityStateBar({ row }: { row: DashboardBreakdown }) {
  const total = Math.max(1, row.total);
  const parts = [["online", row.online], ["suspect", row.suspect], ["offline", row.offline], ["maintenance", row.maintenance], ["unknown", row.unknown]] as const;
  return <div className="noc-state-bar" aria-label={`${row.label} availability breakdown`}>
    {parts.map(([name, value]) => value > 0 ? <span key={name} className={`state-${name}`} style={{ width:`${(value / total) * 100}%` }} /> : null)}
  </div>;
}
