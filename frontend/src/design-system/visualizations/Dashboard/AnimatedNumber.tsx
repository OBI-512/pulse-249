import { useEffect, useState } from "react";
const formatter = new Intl.NumberFormat("en-US");
export function formatDashboardCount(value: number) { return formatter.format(value); }
export function AnimatedNumber({ value }: { value: number }) {
  const [shown, setShown] = useState(value);
  useEffect(() => {
    const start = shown;
    const delta = value - start;
    if (!delta) return;
    const started = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - started) / 360);
      setShown(Math.round(start + delta * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value]);
  return <>{formatDashboardCount(shown)}</>;
}
