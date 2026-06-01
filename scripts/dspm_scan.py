#!/usr/bin/env python3
"""Prowler DSPM Scan - simulated Data Security Posture Management demo.

Standalone script. No real cloud calls, no real LLM. Everything is faked
to demonstrate what a DSPM workflow on top of Prowler could look like.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    _RICH = True
    _console = Console()
except ImportError:
    _RICH = False
    _console = None

VERSION = "0.1.0"
VALID_PROVIDERS = ("aws", "azure", "gcp")
VALID_SERVICES = ("s3", "rds", "dynamodb")

CATALOG = [
    {"datastore_id": "s3://acme-customers-prod", "service": "s3", "classification": "PII", "confidence": 0.96, "risk_score": 10, "evidence": "Found SSN-format strings in 7/10 sampled objects; email + full name combinations in 9/10", "recommendation": "Enable SSE-KMS encryption, attach restrictive bucket policy, enable Block Public Access", "encrypted": False, "public": True},
    {"datastore_id": "s3://acme-payments-archive", "service": "s3", "classification": "Financial", "confidence": 0.91, "risk_score": 9, "evidence": "Detected credit card PANs (Luhn-valid) and IBAN strings in 8/10 sampled archives", "recommendation": "Enable SSE-KMS, turn on versioning + Object Lock, restrict to PCI-scoped IAM roles", "encrypted": False, "public": False},
    {"datastore_id": "s3://acme-marketing-assets", "service": "s3", "classification": "Public", "confidence": 0.99, "risk_score": 1, "evidence": "All 10 samples are PNG/JPG marketing collateral with no detected sensitive content", "recommendation": "No action required; current public-read ACL is intentional", "encrypted": True, "public": True},
    {"datastore_id": "rds://patients-db-primary", "service": "rds", "classification": "Health", "confidence": 0.89, "risk_score": 8, "evidence": "Rows contain ICD-10 codes, patient identifiers, and diagnosis free-text in 10/10 sampled rows", "recommendation": "Disable public accessibility, place behind a private subnet, restrict to HIPAA-scoped roles", "encrypted": True, "public": True},
    {"datastore_id": "rds://payroll-prod", "service": "rds", "classification": "Financial", "confidence": 0.93, "risk_score": 7, "evidence": "Columns include salary, tax_id, and bank_account in 10/10 sampled rows", "recommendation": "Enable automated backups with 30-day retention, rotate KMS key, enforce least-privilege role", "encrypted": True, "public": False},
    {"datastore_id": "rds://analytics-warehouse", "service": "rds", "classification": "Unknown", "confidence": 0.42, "risk_score": 3, "evidence": "Sampled rows contain aggregate counts and anonymized identifiers; insufficient signal for confident classification", "recommendation": "Re-run with expanded sample size; verify anonymization invariants documented", "encrypted": True, "public": False},
    {"datastore_id": "dynamodb://user-sessions", "service": "dynamodb", "classification": "PII", "confidence": 0.84, "risk_score": 7, "evidence": "Items contain user_email and session_token fields in 10/10 sampled items", "recommendation": "Set TTL to 24h, enable PITR, rotate session signing key quarterly", "encrypted": True, "public": False},
    {"datastore_id": "dynamodb://feature-flags", "service": "dynamodb", "classification": "Public", "confidence": 0.97, "risk_score": 1, "evidence": "Items contain feature names and boolean flags only; no sensitive content detected", "recommendation": "No action required", "encrypted": True, "public": False},
    {"datastore_id": "dynamodb://billing-events", "service": "dynamodb", "classification": "Financial", "confidence": 0.88, "risk_score": 8, "evidence": "Items contain charge_amount, last4_cc, and merchant_id in 9/10 sampled items", "recommendation": "Enable encryption at rest with customer-managed KMS, restrict global table replicas to PCI regions", "encrypted": False, "public": False},
]

BANNER = r"""
 ____                    _              ____  ____  ____  __  __
|  _ \ _ __ _____      _| | ___ _ __   |  _ \/ ___||  _ \|  \/  |
| |_) | '__/ _ \ \ /\ / / |/ _ \ '__|  | | | \___ \| |_) | |\/| |
|  __/| | | (_) \ V  V /| |  __/ |     | |_| |___) |  __/| |  | |
|_|   |_|  \___/ \_/\_/ |_|\___|_|     |____/|____/|_|   |_|  |_|
"""


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dspm_scan.py",
        description="Prowler DSPM Scan - simulated data security posture management.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--provider", choices=VALID_PROVIDERS, default="aws", help="Cloud provider")
    p.add_argument("--service", type=_csv, default=list(VALID_SERVICES), help="Comma-separated services to scan (s3,rds,dynamodb)")
    p.add_argument("--region", default="us-east-1", help="Cloud region")
    p.add_argument("--output-formats", type=_csv, default=["json", "html"], help="Comma-separated output formats (json,html)")
    p.add_argument("--output-directory", default="./dspm-output", help="Directory for output files")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = p.parse_args()

    bad_services = [s for s in args.service if s not in VALID_SERVICES]
    if bad_services:
        p.error(f"invalid --service values: {', '.join(bad_services)} (allowed: {', '.join(VALID_SERVICES)})")
    bad_formats = [f for f in args.output_formats if f not in ("json", "html")]
    if bad_formats:
        p.error(f"invalid --output-formats values: {', '.join(bad_formats)} (allowed: json, html)")
    return args


def info(msg: str) -> None:
    if _RICH:
        _console.print(msg)
    else:
        print(msg)


def print_banner() -> None:
    if _RICH:
        _console.print(Text(BANNER, style="bold cyan"))
        _console.print(Panel.fit(
            f"[bold]Prowler DSPM Scan v{VERSION}[/bold]\n"
            f"[dim]Data Security Posture Management - powered by Lighthouse AI[/dim]",
            border_style="cyan",
        ))
    else:
        print(BANNER)
        print(f"Prowler DSPM Scan v{VERSION}")
        print("Data Security Posture Management - powered by Lighthouse AI")
        print("-" * 60)


def discover(services: list[str], region: str) -> list[dict]:
    info(f"\n[bold]>[/bold] Discovering datastores in AWS region [cyan]{region}[/cyan]..." if _RICH else f"\n> Discovering datastores in AWS region {region}...")
    time.sleep(0.3)
    selected = [d for d in CATALOG if d["service"] in services]
    by_service: dict[str, int] = {}
    for d in selected:
        by_service[d["service"]] = by_service.get(d["service"], 0) + 1
    for svc in services:
        count = by_service.get(svc, 0)
        time.sleep(0.3)
        info(f"  [green]found[/green] {count} {svc} datastore(s)" if _RICH else f"  found {count} {svc} datastore(s)")
    return selected


def sample(datastores: list[dict], verbose: bool) -> None:
    info("\n[bold]>[/bold] Sampling 10 objects/rows from each datastore..." if _RICH else "\n> Sampling 10 objects/rows from each datastore...")
    if _RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=_console,
            transient=False,
        ) as progress:
            task = progress.add_task("sampling", total=len(datastores))
            for d in datastores:
                progress.update(task, description=f"sampling {d['datastore_id']}")
                time.sleep(0.3)
                progress.advance(task)
    else:
        for d in datastores:
            print(f"  sampling {d['datastore_id']}...")
            time.sleep(0.3)
    if verbose:
        info(f"  [dim]sampled {len(datastores) * 10} total records[/dim]" if _RICH else f"  sampled {len(datastores) * 10} total records")


def classify(datastores: list[dict]) -> None:
    info("\n[bold]>[/bold] Classifying samples with Lighthouse AI..." if _RICH else "\n> Classifying samples with Lighthouse AI...")
    for d in datastores:
        time.sleep(0.3)
        cls = d["classification"]
        conf = d["confidence"]
        risk = d["risk_score"]
        if _RICH:
            color = {"PII": "magenta", "Financial": "yellow", "Health": "red", "Public": "green", "Unknown": "dim"}.get(cls, "white")
            _console.print(
                f"  [bold]{d['datastore_id']}[/bold] -> "
                f"[{color}]{cls}[/{color}] "
                f"(confidence={conf:.2f}, risk={risk})"
            )
        else:
            print(f"  {d['datastore_id']} -> {cls} (confidence={conf:.2f}, risk={risk})")


def write_json(rows: list[dict], path: str, meta: dict) -> None:
    payload = {"metadata": meta, "datastores": rows}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def _risk_color(risk: int) -> str:
    if risk >= 8:
        return "#d9342b"
    if risk >= 5:
        return "#e88a1a"
    if risk >= 3:
        return "#e0c020"
    return "#2e9d4a"


def write_html(rows: list[dict], path: str, meta: dict) -> None:
    ts = meta["generated_at"]
    body_rows = []
    for d in rows:
        color = _risk_color(d["risk_score"])
        body_rows.append(
            "<tr>"
            f"<td class='mono'>{d['datastore_id']}</td>"
            f"<td>{d['service']}</td>"
            f"<td><span class='pill'>{d['classification']}</span></td>"
            f"<td>{d['confidence']:.2f}</td>"
            f"<td class='risk' style='background:{color}'>{d['risk_score']}</td>"
            f"<td>{d['evidence']}</td>"
            f"<td>{d['recommendation']}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Prowler DSPM Catalog</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #1f2329; }}
  header {{ background: linear-gradient(135deg, #0b2545 0%, #134074 100%); color: #fff; padding: 28px 40px; }}
  header h1 {{ margin: 0; font-size: 24px; letter-spacing: 0.3px; }}
  header p {{ margin: 6px 0 0; opacity: 0.85; font-size: 13px; }}
  main {{ padding: 24px 40px 60px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(15,23,42,0.08); border-radius: 6px; overflow: hidden; }}
  th, td {{ padding: 12px 14px; text-align: left; font-size: 13px; vertical-align: top; border-bottom: 1px solid #eceef2; }}
  th {{ background: #eef1f6; font-weight: 600; color: #2b3340; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
  tr:last-child td {{ border-bottom: none; }}
  td.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
  td.risk {{ color: #fff; font-weight: 700; text-align: center; width: 48px; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #e6ecf5; color: #134074; font-weight: 600; font-size: 11px; }}
  footer {{ padding: 16px 40px; color: #6b7280; font-size: 12px; border-top: 1px solid #e5e7eb; background: #fff; }}
</style>
</head>
<body>
<header>
  <h1>Prowler DSPM Catalog</h1>
  <p>Provider: {meta['provider']} &middot; Region: {meta['region']} &middot; Services: {', '.join(meta['services'])} &middot; Datastores: {len(rows)}</p>
</header>
<main>
  <table>
    <thead><tr>
      <th>Datastore</th><th>Service</th><th>Classification</th><th>Confidence</th><th>Risk</th><th>Evidence</th><th>Recommendation</th>
    </tr></thead>
    <tbody>
      {''.join(body_rows)}
    </tbody>
  </table>
</main>
<footer>Generated by Prowler DSPM &middot; classification powered by Lighthouse AI &middot; {ts}</footer>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def summarize(rows: list[dict]) -> None:
    by_class: dict[str, int] = {}
    for d in rows:
        by_class[d["classification"]] = by_class.get(d["classification"], 0) + 1
    top = sorted(rows, key=lambda r: r["risk_score"], reverse=True)[:3]

    if _RICH:
        _console.print()
        t = Table(title="Classification summary", show_header=True, header_style="bold")
        t.add_column("Classification")
        t.add_column("Datastores", justify="right")
        for cls, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
            t.add_row(cls, str(n))
        _console.print(t)
        _console.print("\n[bold]Top risks[/bold]")
        for d in top:
            _console.print(f"  [red]risk={d['risk_score']:>2}[/red]  {d['datastore_id']}  [dim]({d['classification']})[/dim]")
    else:
        print("\nClassification summary:")
        for cls, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
            print(f"  {cls}: {n}")
        print("\nTop risks:")
        for d in top:
            print(f"  risk={d['risk_score']:>2}  {d['datastore_id']}  ({d['classification']})")


def main() -> int:
    args = parse_args()
    print_banner()

    if args.provider != "aws":
        info(f"\n[yellow]Provider '{args.provider}' is not yet supported. Only 'aws' is implemented.[/yellow]" if _RICH else f"\nProvider '{args.provider}' is not yet supported. Only 'aws' is implemented.")
        return 0

    datastores = discover(args.service, args.region)
    if not datastores:
        info("\nNo datastores discovered. Nothing to do.")
        return 0

    sample(datastores, args.verbose)
    classify(datastores)

    rows = sorted(datastores, key=lambda r: r["risk_score"], reverse=True)
    os.makedirs(args.output_directory, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provider": args.provider,
        "region": args.region,
        "services": args.service,
        "tool": f"Prowler DSPM Scan v{VERSION}",
    }

    written = []
    if "json" in args.output_formats:
        json_path = os.path.join(args.output_directory, "dspm-catalog.json")
        write_json(rows, json_path, meta)
        written.append(json_path)
    if "html" in args.output_formats:
        html_path = os.path.join(args.output_directory, "dspm-report.html")
        write_html(rows, html_path, meta)
        written.append(html_path)

    summarize(rows)

    info("")
    for p in written:
        info(f"[green]wrote[/green] {os.path.abspath(p)}" if _RICH else f"wrote {os.path.abspath(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
