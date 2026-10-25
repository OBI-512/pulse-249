import { forwardRef, type InputHTMLAttributes } from "react";
import styles from "./Checkbox.module.css";

export interface CheckboxProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
  unstyled?: boolean;
}

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(function Checkbox(
  { label, unstyled = false, className = "", ...props },
  ref,
) {
  const control = <input {...props} ref={ref} type="checkbox" className={unstyled ? className : [styles.control, className].filter(Boolean).join(" ")} />;
  if (!label) return control;
  return <label className={styles.label}>{control}<span>{label}</span></label>;
});
