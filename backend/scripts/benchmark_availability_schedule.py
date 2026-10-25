#!/usr/bin/env python3
"""Synthetic C1 scheduler distribution benchmark (no live devices required)."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import uuid


def distribution(device_count: int, interval_seconds: int) -> Counter[int]:
    counts: Counter[int] = Counter()
    # Use deterministic UUID5 identifiers so the benchmark is repeatable while
    # exercising the same UUID-modulo staggering rule used for newly registered
    # devices.
    namespace = uuid.UUID("49907fdc-2ee2-49e4-ad29-2befdf66fb35")
    for index in range(device_count):
        device_id = uuid.uuid5(namespace, f"device:{index}")
        counts[device_id.int % interval_seconds] += 1
    for second in range(interval_seconds):
        counts.setdefault(second, 0)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=20_000)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--max-factor", type=float, default=1.35)
    args = parser.parse_args()
    if args.devices <= 0 or args.interval <= 0:
        raise SystemExit("devices and interval must be positive")

    counts = distribution(args.devices, args.interval)
    average = args.devices / args.interval
    peak = max(counts.values())
    minimum = min(counts.values())
    p95 = sorted(counts.values())[math.ceil(len(counts) * 0.95) - 1]
    allowed_peak = math.ceil(average * args.max_factor)
    passed = peak <= allowed_peak
    report = {
        "devices": args.devices,
        "interval_seconds": args.interval,
        "average_checks_per_second": round(average, 3),
        "minimum_slot": minimum,
        "p95_slot": p95,
        "peak_slot": peak,
        "allowed_peak": allowed_peak,
        "max_factor": args.max_factor,
        "pass": passed,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
