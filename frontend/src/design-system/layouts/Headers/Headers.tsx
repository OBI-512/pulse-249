import type { ReactNode } from "react";
import styles from "./Headers.module.css";

export function PageHeader({ title, help, description, actions, className = "" }: {
  title: string;
  help?: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return <div className={`page-heading ${styles.page}${className ? ` ${className}` : ""}`}>
    <div className={styles.copy}>
      <h2 className={help ? "hover-help-title" : undefined} data-help={help}>{title}</h2>
      {description ? <div className={styles.description}>{description}</div> : null}
    </div>
    {actions ? <ActionBar>{actions}</ActionBar> : null}
  </div>;
}

export function SectionHeader({ title, help, description, actions, className = "" }: {
  title: string;
  help?: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return <div className={`panel-header ${styles.section}${className ? ` ${className}` : ""}`}>
    <div className={styles.copy}>
      <h3 className={help ? "hover-help-title" : undefined} data-help={help}>{title}</h3>
      {description ? <div className={styles.description}>{description}</div> : null}
    </div>
    {actions}
  </div>;
}

export function ActionBar({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`button-row ${styles.actions}${className ? ` ${className}` : ""}`}>{children}</div>;
}
