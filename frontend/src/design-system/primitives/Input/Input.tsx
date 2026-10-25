import { forwardRef, type InputHTMLAttributes } from "react";
import styles from "./Input.module.css";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean;
  unstyled?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { invalid = false, unstyled = false, className = "", ...props },
  ref,
) {
  return (
    <input
      {...props}
      ref={ref}
      aria-invalid={invalid || props["aria-invalid"] || undefined}
      className={unstyled ? className : [styles.root, invalid ? styles.invalid : "", className].filter(Boolean).join(" ")}
    />
  );
});
