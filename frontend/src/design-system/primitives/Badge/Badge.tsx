import type { HTMLAttributes, ReactNode } from "react";
import styles from "./Badge.module.css";

export type BadgeTone = "neutral" | "accent" | "success" | "warning" | "danger" | "violet";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  children: ReactNode;
}

export function Badge({ tone = "neutral", className = "", children, ...props }: BadgeProps) {
  return <span {...props} className={[styles.root, styles[tone], className].filter(Boolean).join(" ")}>{children}</span>;
}
