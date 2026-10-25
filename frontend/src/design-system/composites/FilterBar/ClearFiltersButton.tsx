import styles from "./FilterBar.module.css";
export function ClearFiltersButton({ onClick, disabled=false, label="Clear Filters", className="" }: { onClick:()=>void; disabled?:boolean; label?:string; className?:string }) {
  return <button type="button" className={`secondary small ${styles.clear}${className ? ` ${className}` : ""}`} disabled={disabled} onClick={onClick}>{label}</button>;
}
