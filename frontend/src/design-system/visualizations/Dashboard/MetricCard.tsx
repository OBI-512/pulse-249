import { AnimatedNumber } from "./AnimatedNumber";
import { DashboardIcon } from "./DashboardIcon";
export function DashboardMetricCard({ icon, label, value, detail, tone }: { icon: string; label: string; value: number; detail: string; tone: string }) {
  return <article className={`noc-metric tone-${tone}`}>
    <span className="noc-metric-icon"><DashboardIcon name={icon} /></span>
    <div><span>{label}</span><strong><AnimatedNumber value={value} /></strong><small>{detail}</small></div>
  </article>;
}
