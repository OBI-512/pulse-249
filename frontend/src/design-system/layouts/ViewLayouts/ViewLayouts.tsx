import type { ReactNode } from "react";
import { PageLayout, PageContent } from "../PageLayout";
import styles from "./ViewLayouts.module.css";

type CommonProps = { children: ReactNode; className?: string };

export function ListViewLayout({ children, className = "" }: CommonProps) {
  return <PageLayout className={`${styles.list}${className ? ` ${className}` : ""}`}><PageContent>{children}</PageContent></PageLayout>;
}

export function DetailViewLayout({ children, className = "" }: CommonProps) {
  return <PageLayout className={`${styles.detail}${className ? ` ${className}` : ""}`}><PageContent>{children}</PageContent></PageLayout>;
}

export function DashboardLayout({ children, className = "" }: CommonProps) {
  return <PageLayout className={`${styles.dashboard}${className ? ` ${className}` : ""}`}><PageContent>{children}</PageContent></PageLayout>;
}

export function SettingsLayout({ children, className = "" }: CommonProps) {
  return <PageLayout className={`${styles.settings}${className ? ` ${className}` : ""}`}><PageContent>{children}</PageContent></PageLayout>;
}

export function SplitView({ primary, secondary, className = "" }: { primary: ReactNode; secondary: ReactNode; className?: string }) {
  return <div className={`${styles.split}${className ? ` ${className}` : ""}`}><div className={styles.primary}>{primary}</div><div className={styles.secondary}>{secondary}</div></div>;
}
