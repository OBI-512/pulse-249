import styles from "./Tabs.module.css";

export type TabOption<T extends string> = {
  id: T;
  label: string;
  visible?: boolean;
  disabled?: boolean;
  title?: string;
  closable?: boolean;
};

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  onClose,
  className = "",
  ariaLabel,
}: {
  tabs: TabOption<T>[];
  value: T;
  onChange: (value: T) => void;
  onClose?: (value: T) => void;
  className?: string;
  ariaLabel?: string;
}) {
  const visibleTabs = tabs.filter((tab) => tab.visible !== false);

  return (
    <div
      className={`${styles.root}${className ? ` ${className}` : ""}`}
      role="tablist"
      aria-label={ariaLabel}
    >
      {visibleTabs.map((tab) => {
        const selected = value === tab.id;
        return (
          <div key={tab.id} className={styles.item} role="presentation">
            <button
              type="button"
              role="tab"
              aria-selected={selected}
              disabled={tab.disabled}
              title={tab.title}
              className={`${styles.tab}${selected ? ` ${styles.active}` : ""}${tab.closable ? ` ${styles.closableTab}` : ""}`}
              onClick={() => { if (!selected) onChange(tab.id); }}
            >
              {tab.label}
            </button>
            {tab.closable && onClose ? (
              <button
                type="button"
                className={styles.close}
                aria-label={`Close ${tab.label}`}
                title={`Close ${tab.label}`}
                onClick={() => onClose(tab.id)}
              >
                <span aria-hidden="true">×</span>
              </button>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
