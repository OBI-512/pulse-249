import type { ButtonHTMLAttributes, ReactNode } from "react";
import styles from "./IconButton.module.css";

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  label: string;
  icon: ReactNode;
  size?: "sm" | "md";
}

export function IconButton({ label, icon, size = "md", className = "", type = "button", ...props }: IconButtonProps) {
  return (
    <button
      {...props}
      type={type}
      aria-label={label}
      title={props.title ?? label}
      className={[styles.root, styles[size], className].filter(Boolean).join(" ")}
    >
      <span className={styles.icon} aria-hidden="true">{icon}</span>
    </button>
  );
}
