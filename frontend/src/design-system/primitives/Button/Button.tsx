import type { ButtonHTMLAttributes, ReactNode } from "react";
import styles from "./Button.module.css";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  fullWidth?: boolean;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  unstyled?: boolean;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  fullWidth = false,
  leadingIcon,
  trailingIcon,
  unstyled = false,
  className = "",
  disabled,
  children,
  type = "button",
  ...props
}: ButtonProps) {
  if (unstyled) {
    return (
      <button
        {...props}
        type={type}
        className={className}
        disabled={disabled || loading}
        aria-busy={loading || undefined}
      >
        {children}
      </button>
    );
  }

  const classes = [
    styles.root,
    styles[variant],
    styles[size],
    fullWidth ? styles.fullWidth : "",
    className,
  ].filter(Boolean).join(" ");

  return (
    <button
      {...props}
      type={type}
      className={classes}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
    >
      {leadingIcon && <span className={styles.icon} aria-hidden="true">{leadingIcon}</span>}
      <span className={styles.label}>{loading ? "Working..." : children}</span>
      {trailingIcon && <span className={styles.icon} aria-hidden="true">{trailingIcon}</span>}
    </button>
  );
}
