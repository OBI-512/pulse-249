export function formatDate(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function confidence(value: number) {
  return `${Math.round(value * 100)}%`;
}
