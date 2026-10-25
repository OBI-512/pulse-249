#!/usr/bin/env python3
import argparse, csv, json, re
from collections import Counter
from pathlib import Path

COMMERCIAL_RE = re.compile(r"commercial|proprietary|non[- ]commercial|evaluation|trial", re.I)
OBLIGATIONS = {
    "restricted": "Copyleft/restricted license detected. Preserve applicable notices/license text and review source/redistribution obligations for the distributed component.",
    "reciprocal": "Reciprocal/weak-copyleft license detected. Preserve notices/license text and review reciprocal obligations for modifications/linking/distribution.",
    "notice": "Notice/attribution license detected. Preserve required copyright, attribution and license notices in distributions.",
    "unencumbered": "Generally permissive/unencumbered classification; retain any package notices supplied by the component.",
    "unknown": "License classification is unknown or non-standard. Manual legal/license review is required before commercial distribution if this component is material.",
}

def norm(v): return "" if v is None else str(v).strip()

def classify(item):
    category=norm(item.get("classification")).lower() or "unknown"
    license_name=norm(item.get("license")) or "UNKNOWN"
    flags=[]
    if category in {"restricted","reciprocal"}: flags.append("COPYLEFT_OR_RECIPROCAL")
    if category == "unknown" or license_name.upper() in {"UNKNOWN","NONE",""}: flags.append("UNKNOWN")
    if COMMERCIAL_RE.search(license_name): flags.append("COMMERCIAL_OR_PROPRIETARY")
    obligation=OBLIGATIONS.get(category, OBLIGATIONS["unknown"])
    if COMMERCIAL_RE.search(license_name):
        obligation += " Commercial/proprietary terms detected; explicit terms review is required before redistribution."
    return category, flags, obligation

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--inventory",required=True)
    ap.add_argument("--json-output",required=True)
    ap.add_argument("--csv-output",required=True)
    a=ap.parse_args()
    inv=json.loads(Path(a.inventory).read_text(encoding="utf-8"))
    rows=[]
    for item in inv.get("licenses",[]):
        category,flags,obligation=classify(item)
        rows.append({"package":norm(item.get("package")),"version":norm(item.get("version")),"license":norm(item.get("license")) or "UNKNOWN","classification":category,"flags":";".join(flags),"obligation":obligation,"target":norm(item.get("target"))})
    if not rows: raise SystemExit("License inventory is empty.")
    cats=Counter(r["classification"] for r in rows)
    flags=Counter(f for r in rows for f in r["flags"].split(";") if f)
    summary={"result":"REVIEW_REGISTER_GENERATED","records":len(rows),"classification_counts":dict(sorted(cats.items())),"flag_counts":dict(sorted(flags.items())),"policy_note":"Flags document obligations/review needs; they are not automatic evidence of license non-compliance. Legal clearance remains a release/commercial-distribution responsibility where required.","records_detail":rows}
    Path(a.json_output).write_text(json.dumps(summary,indent=2),encoding="utf-8")
    with open(a.csv_output,"w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print("===== B4 LICENSE OBLIGATION REVIEW =====")
    print("Records:",len(rows)); print("Classifications:",dict(sorted(cats.items()))); print("Flags:",dict(sorted(flags.items())))
    print("JSON:",a.json_output); print("CSV:",a.csv_output)

if __name__=="__main__": main()
