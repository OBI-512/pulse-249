import type { ReactNode } from "react";
import styles from "./PageLayout.module.css";

export function PageLayout({ children, className = "", density = "default" }: {
  children: ReactNode;
  className?: string;
  density?: "default" | "compact";
}) {
  return <div className={`${styles.root} ${density === "compact" ? styles.compact : ""}${className ? ` ${className}` : ""}`.trim()}>{children}</div>;
}

export function PageContent({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`${styles.content}${className ? ` ${className}` : ""}`}>{children}</div>;
}
