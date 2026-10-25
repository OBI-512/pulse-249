import type { ReactElement, ReactNode } from "react";
import styles from "./Tooltip.module.css";

export interface TooltipProps {
  content: ReactNode;
  children: ReactElement;
  placement?: "top" | "bottom";
}

export function Tooltip({ content, children, placement = "top" }: TooltipProps) {
  return (
    <span className={styles.root} tabIndex={0}>
      {children}
      <span className={[styles.tooltip, styles[placement]].join(" ")} role="tooltip">{content}</span>
    </span>
  );
}
