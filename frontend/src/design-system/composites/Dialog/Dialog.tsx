import type { FormEventHandler, HTMLAttributes, MouseEventHandler, ReactNode } from "react";
import styles from "./Dialog.module.css";

type DialogBackdropProps = HTMLAttributes<HTMLDivElement> & {
  children: ReactNode;
};

export function DialogBackdrop({ className = "", children, ...props }: DialogBackdropProps) {
  return <div {...props} className={[styles.backdrop, "dialog-backdrop", className].filter(Boolean).join(" ")}>{children}</div>;
}

type DialogCardProps = Omit<HTMLAttributes<HTMLElement>, "onSubmit"> & {
  as?: "section" | "form";
  wide?: boolean;
  danger?: boolean;
  children: ReactNode;
  onSubmit?: FormEventHandler<HTMLFormElement>;
};

export function DialogCard({
  as = "section",
  wide = false,
  danger = false,
  className = "",
  children,
  onSubmit,
  ...props
}: DialogCardProps) {
  const classes = [styles.card, "dialog-card", wide ? styles.wide : "", wide ? "dialog-wide" : "", danger ? styles.danger : "", danger ? "dialog-danger" : "", className]
    .filter(Boolean)
    .join(" ");

  if (as === "form") {
    return <form {...props} className={classes} onSubmit={onSubmit}>{children}</form>;
  }
  return <section {...props} className={classes}>{children}</section>;
}

type DialogHeaderProps = {
  eyebrow: string;
  title: string;
  titleId?: string;
  onClose?: () => void;
};

export function DialogHeader({ eyebrow, title, titleId, onClose }: DialogHeaderProps) {
  return (
    <div className={`${styles.header} dialog-header`}>
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h3 id={titleId}>{title}</h3>
      </div>
      {onClose ? <button type="button" className={`${styles.close} dialog-close`} aria-label="Close dialog" onClick={onClose}>×</button> : null}
    </div>
  );
}

export function DialogMessage({ className = "", children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={[styles.message, "dialog-message", className].filter(Boolean).join(" ")}>{children}</div>;
}

export function DialogBody({ className = "", children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={[styles.body, "dialog-body", className].filter(Boolean).join(" ")}>{children}</div>;
}

export function DialogActions({ className = "", children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={[styles.actions, "dialog-actions", className].filter(Boolean).join(" ")}>{children}</div>;
}

export type DialogOutsideMouseHandler = MouseEventHandler<HTMLDivElement>;
