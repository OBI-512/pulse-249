#!/usr/bin/env python3
import argparse, json, fnmatch
from pathlib import Path

HIGH = {"HIGH", "CRITICAL"}

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def trivy_items(doc, prop):
    out = []
    for result in doc.get("Results") or []:
        for item in result.get(prop) or []:
            x = dict(item)
            x["_target"] = result.get("Target") or ""
            x["_type"] = result.get("Type") or ""
            out.append(x)
    return out

def suffix(path):
    return str(path).replace("\\","/")

def allowed_semgrep(item, policy):
    rule = item.get("check_id")
    path = suffix(item.get("path",""))
    for exc in policy.get("semgrep_exceptions", []):
        if rule == exc["rule"] and path.endswith(exc["path_suffix"]):
            return True
    return False

def allowed_misconfig(item, policy):
    target = suffix(item.get("_target",""))
    for exc in policy.get("misconfiguration_exceptions", []):
        if item.get("ID") == exc["id"] and target.endswith(exc["target"]):
            return True
    return False

def allowed_image_vuln(name, item, policy):
    exc = (policy.get("runtime_image_exceptions") or {}).get(name)
    if not exc:
        return False
    return (
        exc.get("target_contains","") in suffix(item.get("_target",""))
        and item.get("_type") == exc.get("type")
        and item.get("PkgName") == exc.get("package")
        and item.get("VulnerabilityID") in set(exc.get("allowed_fixable_high_critical_ids", []))
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--policy", required=True)
    args = ap.parse_args()
    evidence = Path(args.evidence)
    policy = load(args.policy)
    failures, warnings = [], []

    fs = load(evidence/"trivy-filesystem.json")
    secrets = trivy_items(fs, "Secrets")
    if secrets:
        failures.append(f"source secrets detected: {len(secrets)}")

    source_vulns = [
        v for v in trivy_items(fs, "Vulnerabilities")
        if v.get("Severity") in HIGH and v.get("FixedVersion")
    ]
    if source_vulns:
        failures.append("fixable source HIGH/CRITICAL vulnerabilities: " +
                        ", ".join(sorted({f"{v.get('VulnerabilityID')}:{v.get('PkgName')}" for v in source_vulns})))

    high_mis = [m for m in trivy_items(fs, "Misconfigurations") if m.get("Severity") in HIGH]
    unapproved_mis = [m for m in high_mis if not allowed_misconfig(m, policy)]
    if unapproved_mis:
        failures.append("unapproved HIGH/CRITICAL misconfigurations: " +
                        ", ".join(sorted({f"{m.get('ID')}@{m.get('_target')}" for m in unapproved_mis})))

    semgrep = load(evidence/"semgrep.json")
    semgrep_blocking = [
        r for r in semgrep.get("results", [])
        if (r.get("extra") or {}).get("severity") in {"ERROR","WARNING"} and not allowed_semgrep(r, policy)
    ]
    if semgrep_blocking:
        failures.append("unapproved Semgrep findings: " +
                        ", ".join(sorted({f"{r.get('check_id')}@{r.get('path')}" for r in semgrep_blocking})))

    image_summary = {}
    for name in ("backend","frontend","postgres","redis"):
        doc = load(evidence/f"trivy-image-{name}.json")
        secrets_i = trivy_items(doc, "Secrets")
        if secrets_i:
            failures.append(f"{name} image secrets detected: {len(secrets_i)}")
        fixable = [
            v for v in trivy_items(doc, "Vulnerabilities")
            if v.get("Severity") in HIGH and v.get("FixedVersion")
        ]
        blocked = [v for v in fixable if not allowed_image_vuln(name, v, policy)]
        if blocked:
            failures.append(f"{name} image fixable HIGH/CRITICAL: " +
                            ", ".join(sorted({f"{v.get('VulnerabilityID')}:{v.get('PkgName')}" for v in blocked})))
        image_summary[name] = {
            "fixable_high_critical": len(fixable),
            "approved_exceptions": len(fixable) - len(blocked),
            "blocked": len(blocked),
        }

    sboms = [
        evidence/"sbom-project.cdx.json",
        evidence/"sbom-backend.cdx.json",
        evidence/"sbom-frontend-runtime.cdx.json",
    ]
    for p in sboms:
        if not p.exists() or p.stat().st_size == 0:
            failures.append(f"missing SBOM: {p.name}")

    license_path = evidence/"license-inventory.json"
    if not license_path.exists():
        failures.append("license inventory missing")
        licenses = []
    else:
        licenses = load(license_path).get("licenses", [])
        if not licenses:
            failures.append("license inventory is empty")

    license_review_path = evidence/"license-obligation-review.json"
    if not license_review_path.exists():
        failures.append("license obligation review missing")
        license_review = {"records":0,"classification_counts":{},"flag_counts":{}}
    else:
        license_review = load(license_review_path)
        if license_review.get("records") != len(licenses):
            failures.append("license obligation review does not reconcile with license inventory")

    result = {
        "result": "PASS" if not failures else "FAIL",
        "failures": failures,
        "warnings": warnings,
        "source": {
            "secrets": len(secrets),
            "fixable_high_critical": len(source_vulns),
            "high_misconfigurations": len(high_mis),
            "unapproved_high_misconfigurations": len(unapproved_mis),
            "semgrep_total": len(semgrep.get("results", [])),
            "semgrep_unapproved": len(semgrep_blocking),
        },
        "images": image_summary,
        "license_records": len(licenses),
        "license_classification_counts": license_review.get("classification_counts", {}),
        "license_flag_counts": license_review.get("flag_counts", {}),
        "sboms": [p.name for p in sboms],
    }
    (evidence/"security-summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("\n================ B4 SECURITY GATE ================")
    print("Result:", result["result"])
    print("Source secrets:", result["source"]["secrets"])
    print("Source fixable HIGH/CRITICAL:", result["source"]["fixable_high_critical"])
    print("Unapproved Semgrep:", result["source"]["semgrep_unapproved"])
    print("Unapproved HIGH misconfig:", result["source"]["unapproved_high_misconfigurations"])
    for name, s in image_summary.items():
        print(f"{name:8} fixable HIGH/CRITICAL={s['fixable_high_critical']} approved={s['approved_exceptions']} blocked={s['blocked']}")
    print("License records:", len(licenses))
    print("License flags:", license_review.get("flag_counts", {}))
    if failures:
        print("Failures:")
        for f in failures:
            print(" -", f)
    print("==================================================")
    raise SystemExit(0 if not failures else 2)

if __name__ == "__main__":
    main()
