import styles from "./AsyncState.module.css";
export function EmptyState({ text, compact = false }: { text: string; compact?: boolean }) {
  return <div className={`${styles.empty}${compact ? ` ${styles.compact}` : ""}`}>{text}</div>;
}
