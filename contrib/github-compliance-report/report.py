#!/usr/bin/env python3
"""Build a SOC 2 / ISO 27001 markdown + CSV report from Prowler compliance CSVs.

Stdlib only. Reads `;`-delimited compliance CSVs produced by the CLI and
writes a grouped markdown report and a combined CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        delimiter = ";" if sample.count(";") >= sample.count(",") else ","
        return list(csv.DictReader(fh, delimiter=delimiter))


def _latest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: p.stat().st_mtime) if paths else None


def _status_of(row: dict[str, str]) -> str:
    return (row.get("STATUS") or row.get("Status") or "").upper()


def _req_id(row: dict[str, str]) -> str:
    return (row.get("REQUIREMENTS_ID") or row.get("Requirements_Id") or "").strip()


def _section(row: dict[str, str]) -> str:
    return (
        row.get("REQUIREMENTS_ATTRIBUTES_SECTION")
        or row.get("REQUIREMENTS_ATTRIBUTES_CATEGORY")
        or row.get("REQUIREMENTS_NAME")
        or _req_id(row)
        or "—"
    )


def _check_id(row: dict[str, str]) -> str:
    return (row.get("CHECKID") or row.get("CheckId") or "").strip()


def _resource(row: dict[str, str]) -> str:
    return (
        row.get("RESOURCENAME")
        or row.get("RESOURCEID")
        or row.get("ResourceName")
        or row.get("ResourceId")
        or ""
    ).strip()


def _extended(row: dict[str, str]) -> str:
    return (row.get("STATUSEXTENDED") or row.get("StatusExtended") or "").strip()


def _group(rows: list[dict[str, str]]) -> dict[str, dict]:
    grouped: dict[str, dict] = {}
    for row in rows:
        req = _req_id(row)
        if not req:
            continue
        bucket = grouped.setdefault(
            req,
            {"section": _section(row), "fails": [], "manual": False, "pass": 0},
        )
        status = _status_of(row)
        if status == "MANUAL" or _check_id(row) in {"", "manual"}:
            bucket["manual"] = True
            continue
        if status == "FAIL":
            bucket["fails"].append(row)
        elif status == "PASS":
            bucket["pass"] += 1
    return grouped


def _row_status(data: dict) -> str:
    if data["fails"]:
        return "FAIL"
    if data["pass"]:
        return "PASS"
    return "MANUAL"


def _table(grouped: dict[str, dict], heading_col: str) -> list[str]:
    lines = [
        f"| {heading_col} | Status | FAIL | Controls |",
        "|---|---|---|---|",
    ]
    if not grouped:
        lines.append("| — | ✅ | 0 | — |")
        return lines
    order = {"FAIL": 0, "PASS": 1, "MANUAL": 2}
    items = sorted(
        grouped.items(),
        key=lambda item: (
            order[_row_status(item[1])],
            item[1]["section"],
            item[0],
        ),
    )
    shown = 0
    manual = 0
    for req, data in items:
        status = _row_status(data)
        if status == "MANUAL":
            manual += 1
            continue
        shown += 1
        lines.append(
            f"| {data['section']} | {status} | {len(data['fails'])} | `{req}` |"
        )
    if not shown:
        lines.append("| — | ✅ | 0 | — |")
    if manual:
        lines.append(
            f"| _({manual} requirements with no automated GitHub check)_ | MANUAL | 0 | — |"
        )
    return lines


def _finding_details(grouped: dict[str, dict], title: str) -> list[str]:
    lines = [f"### {title}", ""]
    any_fail = False
    for req, data in sorted(grouped.items()):
        if not data["fails"]:
            continue
        any_fail = True
        lines.append(f"#### {req} — {data['section']}")
        for row in data["fails"]:
            check = _check_id(row)
            resource = _resource(row)
            extra = _extended(row)
            line = f"- `{check}`"
            if resource:
                line += f" — `{resource}`"
            if extra:
                line += f" — {extra}"
            lines.append(line)
        lines.append("")
    if not any_fail:
        lines.append("_No FAIL findings._")
        lines.append("")
    return lines


def _iac_fail_rows(iac_dir: Path) -> list[dict[str, str]]:
    files = sorted(iac_dir.glob("**/*.ocsf.json")) if iac_dir.is_dir() else []
    path = _latest(files)
    if not path:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    findings = data if isinstance(data, list) else data.get("findings") or []
    rows = []
    for finding in findings:
        status = str(
            finding.get("status_code") or finding.get("status") or ""
        ).upper()
        if "FAIL" not in status:
            continue
        info = finding.get("finding_info") or {}
        rows.append(
            {
                "uid": info.get("uid") or "",
                "title": info.get("title") or finding.get("title") or "finding",
            }
        )
    return rows


def _csv_rows(framework: str, grouped: dict[str, dict]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for req, data in sorted(grouped.items()):
        status = _row_status(data)
        if data["fails"]:
            for row in data["fails"]:
                rows.append(
                    {
                        "FRAMEWORK": framework,
                        "CONTROL": req,
                        "SECTION": data["section"],
                        "STATUS": "FAIL",
                        "CHECK_ID": _check_id(row),
                        "RESOURCE": _resource(row),
                        "DESCRIPTION": _extended(row),
                    }
                )
        else:
            rows.append(
                {
                    "FRAMEWORK": framework,
                    "CONTROL": req,
                    "SECTION": data["section"],
                    "STATUS": status,
                    "CHECK_ID": "",
                    "RESOURCE": "",
                    "DESCRIPTION": "",
                }
            )
    return rows


def write_csv(
    path: Path,
    soc2: dict[str, dict],
    iso: dict[str, dict],
    iac_rows: list[dict[str, str]],
) -> None:
    fieldnames = [
        "FRAMEWORK",
        "CONTROL",
        "SECTION",
        "STATUS",
        "CHECK_ID",
        "RESOURCE",
        "DESCRIPTION",
    ]
    out = _csv_rows("SOC2", soc2) + _csv_rows("ISO27001", iso)
    for row in iac_rows:
        out.append(
            {
                "FRAMEWORK": "IAC",
                "CONTROL": "",
                "SECTION": "IaC / Trivy",
                "STATUS": "FAIL",
                "CHECK_ID": row["uid"],
                "RESOURCE": "",
                "DESCRIPTION": row["title"],
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(out)


def build_report(
    repo: str, out_dir: Path
) -> tuple[str, dict[str, dict], dict[str, dict], list[dict[str, str]]]:
    github_dir = out_dir / "github"
    soc2_csv = _latest(list(github_dir.glob("**/*soc2_github.csv")))
    iso_csv = _latest(list(github_dir.glob("**/*iso27001_2022_github.csv")))
    soc2 = _group(_read_csv(soc2_csv) if soc2_csv else [])
    iso = _group(_read_csv(iso_csv) if iso_csv else [])

    soc2_fail = sum(len(d["fails"]) for d in soc2.values())
    iso_fail = sum(len(d["fails"]) for d in iso.values())
    iac_rows = _iac_fail_rows(out_dir / "iac")
    iac_lines = [
        f"- `{row['uid']}` {row['title']}" if row["uid"] else f"- {row['title']}"
        for row in iac_rows
    ]

    lines = [
        "# Compliance Audit — SOC 2 + ISO 27001",
        "",
        f"_Prowler · `{repo}` · external repository via GitHub token_",
        "",
        f"Mapped **{soc2_fail}** SOC 2 FAIL rows and **{iso_fail}** ISO 27001 FAIL rows "
        "from reviewed GitHub compliance frameworks (not keyword heuristics).",
        "",
        "### SOC 2",
        *_table(soc2, "Section"),
        "",
        "### ISO 27001:2022",
        *_table(iso, "Category"),
        "",
        *_finding_details(soc2, "SOC 2 — FAIL findings"),
        *_finding_details(iso, "ISO 27001:2022 — FAIL findings"),
        "### IaC / Trivy",
        "",
    ]
    if iac_lines:
        lines.append(
            "Scanned the cloned tree. These findings are **not** mapped to SOC 2 / ISO 27001 "
            "(the IaC provider has no those frameworks yet)."
        )
        lines.append("")
        lines.extend(iac_lines)
    else:
        lines.append("_No IaC FAIL findings (or IaC scan skipped)._")
    lines.append("")
    return "\n".join(lines) + "\n", soc2, iso, iac_rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--report-file", type=Path)
    parser.add_argument("--csv-file", type=Path)
    args = parser.parse_args()
    markdown, soc2, iso, iac_rows = build_report(args.repo, args.out_dir)
    dest = args.report_file or (args.out_dir / "audit-report.md")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(markdown, encoding="utf-8")
    csv_dest = args.csv_file or dest.with_suffix(".csv")
    write_csv(csv_dest, soc2, iso, iac_rows)
    print(dest)
    print(csv_dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
