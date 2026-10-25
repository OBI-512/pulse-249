import type { SortState } from "../types";

export function compareSortValues(a: unknown, b: unknown) {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;

  if (typeof a === "boolean" && typeof b === "boolean") {
    return Number(a) - Number(b);
  }

  const aText = String(a).trim();
  const bText = String(b).trim();
  const ipPattern = /^(?:\\d{1,3}\\.){3}\\d{1,3}$/;

  if (ipPattern.test(aText) && ipPattern.test(bText)) {
    const aParts = aText.split(".").map(Number);
    const bParts = bText.split(".").map(Number);
    for (let index = 0; index < 4; index += 1) {
      if (aParts[index] !== bParts[index]) return aParts[index] - bParts[index];
    }
    return 0;
  }

  const aNumber = typeof a === "number" ? a : Number(aText);
  const bNumber = typeof b === "number" ? b : Number(bText);
  if (aText !== "" && bText !== "" && Number.isFinite(aNumber) && Number.isFinite(bNumber)) {
    return aNumber - bNumber;
  }

  const aDate = typeof a === "string" ? Date.parse(a) : Number.NaN;
  const bDate = typeof b === "string" ? Date.parse(b) : Number.NaN;
  if (Number.isFinite(aDate) && Number.isFinite(bDate)) return aDate - bDate;

  return aText.localeCompare(bText, undefined, { numeric: true, sensitivity: "base" });
}


export function sortRows<T>(rows: T[], sort: SortState, getValue: (row: T, key: string) => unknown) {
  return [...rows].sort((a, b) => {
    const result = compareSortValues(getValue(a, sort.key), getValue(b, sort.key));
    return sort.direction === "asc" ? result : -result;
  });
}

export function nextSort(current: SortState, key: string): SortState {
  if (current.key !== key) return { key, direction: "asc" };
  return { key, direction: current.direction === "asc" ? "desc" : "asc" };
}
