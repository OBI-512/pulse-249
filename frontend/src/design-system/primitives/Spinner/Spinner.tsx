import type { HTMLAttributes } from "react";
import styles from "./Spinner.module.css";

export interface SpinnerProps extends HTMLAttributes<HTMLSpanElement> {
  size?: "sm" | "md" | "lg";
  label?: string;
}

export function Spinner({ size = "md", label = "Loading", className = "", ...props }: SpinnerProps) {
  return <span {...props} className={[styles.root, styles[size], className].filter(Boolean).join(" ")} role="status" aria-label={label} />;
}
