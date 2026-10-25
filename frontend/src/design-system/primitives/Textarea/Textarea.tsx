import { forwardRef, type TextareaHTMLAttributes } from "react";
import styles from "./Textarea.module.css";

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  invalid?: boolean;
  unstyled?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { invalid = false, unstyled = false, className = "", ...props },
  ref,
) {
  return (
    <textarea
      {...props}
      ref={ref}
      aria-invalid={invalid || props["aria-invalid"] || undefined}
      className={unstyled ? className : [styles.root, invalid ? styles.invalid : "", className].filter(Boolean).join(" ")}
    />
  );
});
