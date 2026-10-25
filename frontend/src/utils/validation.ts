export function isValidIPv4(value: string): boolean {
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split(".").every((part) => {
    if (part.length > 1 && part.startsWith("0")) return false;
    const octet = Number(part);
    return Number.isInteger(octet) && octet >= 0 && octet <= 255;
  });
}
