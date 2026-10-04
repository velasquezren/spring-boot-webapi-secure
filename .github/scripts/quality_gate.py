#!/usr/bin/env python3
"""Quality Gate de seguridad.

Lee los reportes generados por las herramientas del pipeline y falla (exit 1)
cuando existen hallazgos criticos que superan los umbrales configurados.

Reportes soportados (todos opcionales, se procesan los que existan):
  - Semgrep            JSON   (--semgrep)
  - SpotBugs/FindSecBugs XML  (--spotbugs)
  - OWASP Dependency-Check JSON (--dependency-check)
  - CodeQL u otro SARIF       (--sarif, se puede repetir)

Politica por defecto (ajustable por variables de entorno):
  - Semgrep:          severidad ERROR                      -> critico
  - SpotBugs:         categoria SECURITY y rank <= 12      -> critico
  - Dependency-Check: CVSS >= 9.0 (CRITICAL)               -> critico
                      CVSS >= 7.0 (HIGH)                   -> critico si QG_FAIL_ON_HIGH=true
  - SARIF:            security-severity >= 9.0 o level=error en reglas de seguridad -> critico

  QG_MAX_CRITICAL  numero maximo de hallazgos criticos permitidos (default 0)
  QG_SPOTBUGS_MAX_RANK  rank maximo de SpotBugs considerado critico (default 12)
  QG_FAIL_ON_HIGH  true/false (default false)
  QG_JOB_RESULTS   "job=result,job=result" resultados de jobs previos (needs.*.result)
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_CRITICAL = int(os.getenv("QG_MAX_CRITICAL", "0"))
SPOTBUGS_MAX_RANK = int(os.getenv("QG_SPOTBUGS_MAX_RANK", "12"))
FAIL_ON_HIGH = os.getenv("QG_FAIL_ON_HIGH", "false").lower() == "true"


def finding(tool, severity, rule, location, message):
    return {"tool": tool, "severity": severity, "rule": rule,
            "location": location, "message": " ".join(message.split())[:160]}


def parse_semgrep(path):
    data = json.loads(Path(path).read_text())
    out = []
    for r in data.get("results", []):
        sev = r["extra"].get("severity", "INFO")
        out.append(finding("Semgrep", "CRITICAL" if sev == "ERROR" else sev,
                           r["check_id"].split(".")[-1],
                           f'{r["path"]}:{r["start"]["line"]}',
                           r["extra"].get("message", "")))
    return out


def parse_spotbugs(path):
    root = ET.parse(path).getroot()
    out = []
    for bug in root.iter("BugInstance"):
        rank = int(bug.get("rank", "20"))
        category = bug.get("category", "")
        critical = category == "SECURITY" and rank <= SPOTBUGS_MAX_RANK
        line = bug.find("SourceLine")
        loc = f'{line.get("sourcepath")}:{line.get("start")}' if line is not None else "-"
        msg = bug.findtext("LongMessage") or bug.findtext("ShortMessage") or ""
        out.append(finding("SpotBugs", "CRITICAL" if critical else f"{category} rank {rank}",
                           bug.get("type"), loc, msg))
    return out


def cvss_score(vuln):
    for key in ("cvssv4", "cvssv3", "cvssv2"):
        block = vuln.get(key) or {}
        score = block.get("baseScore") or (block.get("cvssData") or {}).get("baseScore")
        if score is not None:
            return float(score)
    return {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0}.get(vuln.get("severity", "").upper(), 0.0)


def parse_dependency_check(path):
    data = json.loads(Path(path).read_text())
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            score = cvss_score(v)
            if score >= 9.0:
                sev = "CRITICAL"
            elif score >= 7.0:
                sev = "CRITICAL" if FAIL_ON_HIGH else "HIGH"
            else:
                sev = v.get("severity", "LOW").upper()
            out.append(finding("Dependency-Check", sev, v.get("name", "?"),
                               dep.get("fileName", "?"), f'CVSS {score} - {v.get("description", "")}'))
    return out


def parse_sarif(path):
    data = json.loads(Path(path).read_text())
    out = []
    for run in data.get("runs", []):
        tool = run["tool"]["driver"].get("name", "SARIF")
        rules = {}
        for comp in [run["tool"]["driver"]] + run["tool"].get("extensions", []):
            for rule in comp.get("rules", []) or []:
                rules[rule["id"]] = rule
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            props = rule.get("properties", {})
            sec = props.get("security-severity")
            tags = props.get("tags", [])
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            if sec is not None:
                score = float(sec)
                sev = "CRITICAL" if score >= 9.0 or (FAIL_ON_HIGH and score >= 7.0) else (
                    "HIGH" if score >= 7.0 else "MEDIUM")
            else:
                sev = "CRITICAL" if level == "error" and "security" in tags else level.upper()
            loc = "-"
            if res.get("locations"):
                pl = res["locations"][0].get("physicalLocation", {})
                loc = f'{pl.get("artifactLocation", {}).get("uri", "?")}:{pl.get("region", {}).get("startLine", "?")}'
            out.append(finding(tool, sev, res.get("ruleId", "?"), loc,
                               res.get("message", {}).get("text", "")))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--semgrep")
    ap.add_argument("--spotbugs")
    ap.add_argument("--dependency-check")
    ap.add_argument("--sarif", action="append", default=[])
    ap.add_argument("--title", default="Quality Gate de Seguridad")
    args = ap.parse_args()

    sources = [(args.semgrep, parse_semgrep, "Semgrep"),
               (args.spotbugs, parse_spotbugs, "SpotBugs"),
               (args.dependency_check, parse_dependency_check, "Dependency-Check")]
    sources += [(p, parse_sarif, f"SARIF {Path(p).name}") for p in args.sarif]

    findings, analyzed, missing = [], [], []
    for path, parser, name in sources:
        if not path:
            continue
        if Path(path).is_file():
            findings += parser(path)
            analyzed.append(name)
        else:
            missing.append(f"{name} ({path})")

    failed_jobs = []
    for item in filter(None, os.getenv("QG_JOB_RESULTS", "").split(",")):
        job, _, result = item.partition("=")
        if result.strip() in ("failure", "cancelled"):
            failed_jobs.append(f"{job.strip()}={result.strip()}")

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    passed = len(critical) <= MAX_CRITICAL and not failed_jobs and not missing

    tools = sorted({f["tool"] for f in findings} | set(analyzed))
    lines = [f"## {'✅' if passed else '❌'} {args.title}", "",
             f"Umbral: maximo **{MAX_CRITICAL}** hallazgos criticos "
             f"(SpotBugs rank <= {SPOTBUGS_MAX_RANK}, CVSS >= {'7.0' if FAIL_ON_HIGH else '9.0'}).", "",
             "| Herramienta | Total | Criticos |", "|---|---:|---:|"]
    for t in tools:
        tf = [f for f in findings if f["tool"] == t]
        lines.append(f"| {t} | {len(tf)} | {sum(f['severity'] == 'CRITICAL' for f in tf)} |")
    lines.append(f"| **Total** | **{len(findings)}** | **{len(critical)}** |")
    if missing:
        lines += ["", "**Reportes faltantes (el gate falla):** " + ", ".join(missing)]
    if failed_jobs:
        lines += ["", "**Jobs fallidos:** " + ", ".join(failed_jobs)]
    if critical:
        lines += ["", "### Hallazgos criticos", "",
                  "| Herramienta | Regla / CVE | Ubicacion | Detalle |", "|---|---|---|---|"]
        for f in critical:
            lines.append(f"| {f['tool']} | `{f['rule']}` | `{f['location']}` | {f['message'].replace('|', '/')} |")
    lines += ["", f"**Resultado: {'APROBADO' if passed else 'RECHAZADO'}**"]
    report = "\n".join(lines)

    print(report)
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    Path("quality-gate-report.md").write_text(report + "\n", encoding="utf-8")

    for f in critical:
        print(f"::error title={f['tool']} {f['rule']}::{f['location']} {f['message']}")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
