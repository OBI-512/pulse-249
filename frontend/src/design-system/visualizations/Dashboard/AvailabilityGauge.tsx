import { formatDashboardCount } from "./AnimatedNumber";
export function AvailabilityGauge({ label, online, total, primary = false }: { label: string; online: number; total: number; primary?: boolean }) {
  const percent = total ? Math.round((online / total) * 100) : 0;
  return <div className={`noc-gauge ${primary ? "noc-gauge-primary" : "noc-gauge-small"}`} aria-label={`${label}: ${online} of ${total} online`}>
    <div className="noc-gauge-ring" style={{ background: `conic-gradient(from 225deg, #2d8ed8 0deg, #42c78a ${percent * 3.6}deg, rgba(168,196,218,.19) ${percent * 3.6}deg)` }}>
      <div className="noc-gauge-core"><strong>{percent}%</strong><span>online</span><small>{formatDashboardCount(online)} / {formatDashboardCount(total)}</small></div>
    </div>
    <b>{label}</b>
  </div>;
}
