import { forwardRef, type SelectHTMLAttributes } from "react";
import styles from "./Select.module.css";

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  invalid?: boolean;
  unstyled?: boolean;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { invalid = false, unstyled = false, className = "", children, ...props },
  ref,
) {
  return (
    <select
      {...props}
      ref={ref}
      aria-invalid={invalid || props["aria-invalid"] || undefined}
      className={unstyled ? className : [styles.root, invalid ? styles.invalid : "", className].filter(Boolean).join(" ")}
    >
      {children}
    </select>
  );
});
