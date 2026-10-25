import type { ElementType, ReactNode } from "react";
import styles from "./Surface.module.css";

export function Panel({ children, className = "", as: Component = "section" }: { children: ReactNode; className?: string; as?: ElementType }) {
  return <Component className={`panel ${styles.panel}${className ? ` ${className}` : ""}`}>{children}</Component>;
}

export function Card({ children, className = "", as: Component = "article" }: { children: ReactNode; className?: string; as?: ElementType }) {
  return <Component className={`${styles.card}${className ? ` ${className}` : ""}`}>{children}</Component>;
}

export function SectionStack({ children, className = "", compact = false }: { children: ReactNode; className?: string; compact?: boolean }) {
  return <div className={`${styles.stack}${compact ? ` ${styles.compact}` : ""}${className ? ` ${className}` : ""}`}>{children}</div>;
}
