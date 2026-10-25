import type { ReactNode } from "react";
import styles from "./FilterBar.module.css";
export function FilterBar({ children, actions, className="" }: { children:ReactNode; actions?:ReactNode; className?:string }) {
  return <div className={`${styles.root}${className ? ` ${className}` : ""}`}><div className={styles.fields}>{children}</div>{actions ? <div className={styles.actions}>{actions}</div> : null}</div>;
}
