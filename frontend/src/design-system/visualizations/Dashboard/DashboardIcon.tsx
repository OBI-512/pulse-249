import type { ReactNode } from "react";

export function DashboardIcon({ name }: { name: string }) {
  const icons: Record<string, ReactNode> = {
    devices: <><rect x="4" y="5" width="16" height="10" rx="2"/><path d="M8 19h8M12 15v4"/></>,
    online: <><path d="M5 12a7 7 0 0 1 14 0"/><path d="M8 12a4 4 0 0 1 8 0"/><circle cx="12" cy="12" r="1.5"/><path d="M12 13.5V20"/></>,
    offline: <><path d="M5 12a7 7 0 0 1 14 0"/><path d="m7 7 10 10"/><circle cx="12" cy="12" r="1.5"/></>,
    suspect: <><path d="M12 4 21 20H3L12 4Z"/><path d="M12 9v5M12 17h.01"/></>,
    maintenance: <><path d="M14.5 3.5a4 4 0 0 0-3.3 6.3L4.8 16.2a2 2 0 1 0 2.8 2.8l6.4-6.4a4 4 0 0 0 6.3-3.3l-2.7 2.7-2.5-.7-.7-2.5 2.7-2.7-2.6-2.6Z"/><path d="M4 3l3 1 1 3-2 2-3-1-1-3 2-2Z"/><path d="m7 8 12 12"/><path d="m17.5 18.5 1-1 2.5 2.5-1 1-2.5-2.5Z"/></>,
    alarms: <><path d="M6 17h12l-1.5-2.5V10a4.5 4.5 0 0 0-9 0v4.5L6 17Z"/><path d="M10 20h4"/></>,
    discovery: <><circle cx="10.5" cy="10.5" r="5.5"/><path d="m15 15 5 5M10.5 7.5v6M7.5 10.5h6"/></>,
    topology: <><circle cx="12" cy="5" r="2.4"/><circle cx="6" cy="18" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M12 7.4v4.2M12 11.6 6.8 15.8M12 11.6l5.2 4.2"/></>,
    candidates: <><rect x="5" y="4" width="14" height="16" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/></>,
    networks: <><circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="17" r="2.2"/><circle cx="19" cy="17" r="2.2"/><path d="M12 7.2v3.4M12 10.6 6.4 15M12 10.6l5.6 4.4"/></>,
    locations: <><path d="M12 21s6-5.5 6-11a6 6 0 1 0-12 0c0 5.5 6 11 6 11Z"/><circle cx="12" cy="10" r="2"/></>,
  };
  return <svg viewBox="0 0 24 24" className="dashboard-icon" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{icons[name] || icons.devices}</svg>;
}
