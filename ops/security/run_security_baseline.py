#!/usr/bin/env python3
import argparse, datetime, json, os, subprocess, sys, shutil
from pathlib import Path

TRIVY = "aquasec/trivy:0.73.0@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c"
SEMGREP = "semgrep/semgrep:1.172.0@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b"
POSTGRES = "postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
REDIS = "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2"

def run(args, *, cwd=None, allow=False):
    print("\n=====", " ".join(map(str,args[:5])), "=====")
    p = subprocess.run(args, cwd=cwd)
    if p.returncode and not allow:
        raise SystemExit(p.returncode)
    return p.returncode

def mount(src, dst, readonly=False):
    value = f"type=bind,src={Path(src).resolve()},dst={dst}"
    if readonly:
        value += ",readonly"
    return value

def collect_licenses(doc):
    out=[]
    for r in doc.get("Results") or []:
        for item in r.get("Licenses") or []:
            out.append({
                "package": item.get("PkgName"),
                "version": item.get("InstalledVersion"),
                "license": item.get("Name") or item.get("License"),
                "classification": item.get("Category"),
                "target": r.get("Target"),
            })
    return out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--project", default=".")
    ap.add_argument("--evidence")
    args=ap.parse_args()
    project=Path(args.project).resolve()
    stamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence=Path(args.evidence).resolve() if args.evidence else project/"Backup"/"batch_b_b4"/f"validation_{stamp}"
    evidence.mkdir(parents=True, exist_ok=True)
    cache=(project/"Backup"/"batch_b_b4"/"trivy_cache")
    cache.mkdir(parents=True, exist_ok=True)

    backend_img=f"fttwb4sec-backend:{stamp.lower()}"
    frontend_img=f"fttwb4sec-frontend:{stamp.lower()}"
    frontend_deps=f"fttwb4sec-frontend-deps:{stamp.lower()}"

    metadata={
        "timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit":subprocess.check_output(["git","-C",str(project),"rev-parse","HEAD"], text=True).strip(),
        "trivy":TRIVY,"semgrep":SEMGREP,"mode":"B4-blocking-security-baseline"
    }
    (evidence/"scan-metadata.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")

    pm=mount(project,"/workspace",True)
    rm=mount(evidence,"/reports")
    cm=mount(cache,"/root/.cache/trivy")

    try:
        run(["docker","pull",TRIVY]); run(["docker","pull",SEMGREP])

        run(["docker","run","--rm","--mount",pm,"--mount",rm,"--mount",cm,TRIVY,
             "fs","--scanners","vuln,secret,misconfig","--include-dev-deps",
             "--format","json","--output","/reports/trivy-filesystem.json",
             "--skip-dirs","/workspace/Backup","--skip-dirs","/workspace/.git",
             "--skip-dirs","/workspace/frontend/node_modules","--skip-dirs","/workspace/frontend/dist",
             "/workspace"])

        run(["docker","run","--rm","--mount",pm,"--mount",rm,SEMGREP,
             "semgrep","scan","--config","p/default","--oss-only","--metrics","off",
             "--json","--output","/reports/semgrep.json",
             "--exclude","Backup","--exclude",".git","--exclude","frontend/node_modules",
             "--exclude","frontend/dist","--exclude","backend/migrations","--exclude","**/Dockerfile*",
             "/workspace"])

        run(["docker","build","-f",str(project/"backend"/"Dockerfile.prod"),"-t",backend_img,str(project/"backend")])
        run(["docker","build","-f",str(project/"frontend"/"Dockerfile.prod"),"-t",frontend_img,str(project/"frontend")])
        run(["docker","build","-f",str(project/"frontend"/"Dockerfile"),"-t",frontend_deps,str(project/"frontend")])

        targets={"backend":backend_img,"frontend":frontend_img,"postgres":POSTGRES,"redis":REDIS}
        for name,image in targets.items():
            run(["docker","run","--rm","-v","/var/run/docker.sock:/var/run/docker.sock",
                 "--mount",rm,"--mount",cm,TRIVY,"image",
                 "--scanners","vuln,secret,license","--format","json",
                 "--output",f"/reports/trivy-image-{name}.json",image])

        # Dependency license inventory (frontend dev image contains npm node_modules).
        run(["docker","run","--rm","-v","/var/run/docker.sock:/var/run/docker.sock",
             "--mount",rm,"--mount",cm,TRIVY,"image","--scanners","license",
             "--format","json","--output","/reports/trivy-license-frontend-deps.json",
             frontend_deps])

        # SBOMs
        run(["docker","run","--rm","--mount",pm,"--mount",rm,"--mount",cm,TRIVY,
             "fs","--format","cyclonedx","--output","/reports/sbom-project.cdx.json",
             "--skip-dirs","/workspace/Backup","--skip-dirs","/workspace/.git",
             "--skip-dirs","/workspace/frontend/node_modules","/workspace"])
        for name,image in [("backend",backend_img),("frontend-runtime",frontend_img)]:
            run(["docker","run","--rm","-v","/var/run/docker.sock:/var/run/docker.sock",
                 "--mount",rm,"--mount",cm,TRIVY,"image","--format","cyclonedx",
                 "--output",f"/reports/sbom-{name}.cdx.json",image])

        # Aggregate license inventory.
        license_sources=[
            evidence/"trivy-image-backend.json",
            evidence/"trivy-image-frontend.json",
            evidence/"trivy-license-frontend-deps.json",
            evidence/"trivy-image-postgres.json",
            evidence/"trivy-image-redis.json",
        ]
        licenses=[]
        for p in license_sources:
            licenses.extend(collect_licenses(json.loads(p.read_text(encoding="utf-8"))))
        dedup={}
        for x in licenses:
            key=(x.get("package"),x.get("version"),x.get("license"),x.get("target"))
            dedup[key]=x
        inventory_path = evidence/"license-inventory.json"
        inventory_path.write_text(
            json.dumps({"licenses":list(dedup.values())},indent=2),encoding="utf-8"
        )

        license_review=project/"ops"/"security"/"generate_license_review.py"
        run([sys.executable,str(license_review),"--inventory",str(inventory_path),
             "--json-output",str(evidence/"license-obligation-review.json"),
             "--csv-output",str(evidence/"license-obligation-register.csv")])

        evaluator=project/"ops"/"security"/"evaluate_security.py"
        policy=project/"ops"/"security"/"security_policy.json"
        run([sys.executable,str(evaluator),"--evidence",str(evidence),"--policy",str(policy)])
        print("Evidence:", evidence)
    finally:
        # Reclaim validation-only application images; preserve scanner/base caches.
        for image in (backend_img,frontend_img,frontend_deps):
            subprocess.run(["docker","image","rm","-f",image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=="__main__":
    main()
