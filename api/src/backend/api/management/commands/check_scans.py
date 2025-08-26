import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Set

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from rich.align import Align
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from ...db_router import MainRouter
from ...models import Scan, StateChoices


class Command(BaseCommand):
    help = "Check for stuck scans and mark them as failed"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.console = Console(theme=self.get_custom_theme())
        self.logger = None

    def get_custom_theme(self):
        """Create a custom theme without purple colors"""
        return Theme(
            {
                "prompt.choices": "bright_cyan",
                "prompt.default": "bright_white",
                "progress.description": "bright_white",
                "progress.percentage": "bright_cyan",
                "progress.data.speed": "bright_green",
                "progress.spinner": "bright_cyan",
            }
        )

    def setup_logging(self, verbose=False):
        """Setup rich logging handler"""
        if verbose:
            logging.basicConfig(
                level=logging.INFO,
                format="%(message)s",
                datefmt="[%X]",
                handlers=[RichHandler(console=self.console, rich_tracebacks=True)],
            )
            self.logger = logging.getLogger(__name__)
        else:
            # Create a no-op logger
            self.logger = logging.getLogger(__name__)
            self.logger.addHandler(logging.NullHandler())
            self.logger.setLevel(logging.CRITICAL)

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Mark stuck scans as failed without confirmation",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making changes",
        )
        parser.add_argument(
            "--verbose", action="store_true", help="Enable verbose logging"
        )

    def get_celery_app(self):
        """Get the Celery application instance"""
        try:
            from config.celery import celery_app

            return celery_app
        except ImportError:
            raise CommandError("Could not import Celery app from config.celery")

    def get_active_task_ids(self) -> Set[str]:
        """Get all active task IDs from all Celery workers"""
        celery_app = self.get_celery_app()
        inspect = celery_app.control.inspect()

        active_task_ids = set()

        try:
            # Get active tasks from all workers
            active_tasks = inspect.active()
            if active_tasks:
                for worker, tasks in active_tasks.items():
                    for task in tasks:
                        active_task_ids.add(task["id"])

            # Get scheduled tasks from all workers
            scheduled_tasks = inspect.scheduled()
            if scheduled_tasks:
                for worker, tasks in scheduled_tasks.items():
                    for task in tasks:
                        active_task_ids.add(task["id"])

            # Get reserved tasks from all workers
            reserved_tasks = inspect.reserved()
            if reserved_tasks:
                for worker, tasks in reserved_tasks.items():
                    for task in tasks:
                        active_task_ids.add(task["id"])

        except Exception as e:
            if self.logger and hasattr(self.logger, "error"):
                self.logger.error(f"Error connecting to Celery broker: {e}")
            raise CommandError(f"Failed to connect to Celery broker: {e}")

        return active_task_ids

    def find_stuck_scans(self) -> List[Dict]:
        """Find scans that appear to be stuck with interactive progress"""

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=True,
        ) as progress:

            # Step 1: Find executing scans
            scan_task = progress.add_task(
                "🔍 Scanning for executing scans...", total=100
            )

            executing_scans = (
                Scan.objects.using(MainRouter.admin_db)
                .filter(state=StateChoices.EXECUTING)
                .select_related("task__task_runner_task", "provider")
                .exclude(task__isnull=True)
                .exclude(task__task_runner_task__isnull=True)
            )

            progress.update(scan_task, advance=50)
            time.sleep(0.5)  # Small delay for visual effect

            scan_count = executing_scans.count()
            progress.update(
                scan_task,
                advance=50,
                description=f"✅ Found {scan_count} executing scans",
            )
            time.sleep(0.3)

            if scan_count == 0:
                return []

            # Step 2: Get active tasks from Celery
            celery_task = progress.add_task("🔄 Checking Celery workers...", total=100)
            active_task_ids = self.get_active_task_ids()
            progress.update(
                celery_task,
                advance=100,
                description=f"✅ Found {len(active_task_ids)} active tasks",
            )
            time.sleep(0.3)

            # Step 3: Check each scan
            check_task = progress.add_task("🕵️ Analyzing scans...", total=scan_count)
            stuck_scans = []

            for i, scan in enumerate(executing_scans):
                progress.update(
                    check_task,
                    advance=1,
                    description=f"🕵️ Analyzing scan {i + 1}/{scan_count}",
                )

                task_result = scan.task.task_runner_task
                task_id = task_result.task_id

                # Check if task is still active in any worker
                if task_id not in active_task_ids:
                    stuck_scans.append(
                        {
                            "scan": scan,
                            "task_result": task_result,
                        }
                    )

                time.sleep(0.3)  # Small delay for visual effect

            progress.update(
                check_task,
                description=f"✅ Analysis complete - {len(stuck_scans)} stuck scans found",
            )
            time.sleep(2)

        return stuck_scans

    def display_scan_details(self, scan, task_result):
        """Display detailed information about a single scan"""

        # Create scan details panel
        scan_info = Text()
        scan_info.append("🆔 Scan ID: ", style="bold cyan")
        scan_info.append(f"{scan.id}\n", style="cyan")

        scan_info.append("🏢 Tenant ID: ", style="bold bright_blue")
        scan_info.append(f"{scan.tenant_id}\n", style="bright_blue")

        scan_info.append("☁️  Provider: ", style="bold green")
        scan_info.append(f"{scan.provider.provider.upper()}\n", style="green")

        scan_info.append("🔗 Provider UID: ", style="bold green")
        scan_info.append(f"{scan.provider.uid}\n", style="green")

        scan_info.append("⏰ Started At: ", style="bold yellow")
        started_time = (
            scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if scan.started_at
            else "Unknown"
        )
        scan_info.append(f"{started_time}\n", style="yellow")

        scan_info.append("📝 Scan Name: ", style="bold white")
        scan_info.append(f"{scan.name or 'No name'}\n", style="white")

        scan_info.append("🔄 Task ID: ", style="bold blue")
        scan_info.append(f"{task_result.task_id}\n", style="blue")

        scan_info.append("📊 Task Status: ", style="bold red")
        scan_info.append(f"{task_result.status or 'Unknown'}\n", style="red")

        if scan.started_at:
            duration = datetime.now(timezone.utc) - scan.started_at
            scan_info.append("⏱️  Running For: ", style="bold bright_cyan")
            scan_info.append(f"{duration}\n", style="bright_cyan")

        return Panel(
            scan_info,
            title="🚨 Stuck Scan Detected",
            border_style="red",
            title_align="center",
        )

    def display_stuck_scans(self, stuck_scans: List[Dict], force: bool = False):
        """Display stuck scans interactively"""
        if not stuck_scans:
            self.console.print("\n")
            self.console.print(
                Panel(
                    Align.center(
                        "🎉 No stuck scans found!\nAll scans are running properly."
                    ),
                    style="green",
                    title="✅ All Clear",
                )
            )
            return []

        # Show summary first
        self.console.print("\n")
        self.console.print(
            Panel(
                Align.center(
                    f"⚠️ Found {len(stuck_scans)} stuck scan{'s' if len(stuck_scans) != 1 else ''}"
                ),
                style="yellow",
                title="🔍 Detection Results",
            )
        )

        if force:
            self.console.print(
                Panel(
                    Align.center(
                        "🚀 Force mode enabled - marking all stuck scans as failed"
                    ),
                    style="cyan",
                )
            )
            return stuck_scans

        confirmed_scans = []

        for i, stuck_scan in enumerate(stuck_scans, 1):
            self.console.clear()
            self.console.print(
                Panel.fit("🔍 Prowler Stuck Scans Checker", style="bold blue")
            )

            scan = stuck_scan["scan"]
            task_result = stuck_scan["task_result"]

            # Show progress
            progress_text = f"Reviewing scan {i} of {len(stuck_scans)}"
            self.console.print(f"\n{progress_text}", style="dim")

            # Show scan details
            self.console.print("\n")
            self.console.print(self.display_scan_details(scan, task_result))

            # Ask for confirmation
            self.console.print("\n")
            if Confirm.ask(
                "❓ Mark this scan as failed?", console=self.console, default=False
            ):
                confirmed_scans.append(stuck_scan)
                self.console.print("✅ Scan will be marked as failed", style="green")
            else:
                self.console.print("⏭️ Scan skipped", style="yellow")

            # Small pause before next scan (except for last one)
            if i < len(stuck_scans):
                time.sleep(0.5)

        return confirmed_scans

    def mark_scans_as_failed(self, stuck_scans: List[Dict], dry_run: bool = False):
        """Mark stuck scans as failed with interactive progress"""
        if not stuck_scans:
            return

        if dry_run:
            self.console.print("\n")
            self.console.print(
                Panel(
                    Align.center(
                        f"🧪 DRY RUN: Would mark {len(stuck_scans)} scan{'s' if len(stuck_scans) != 1 else ''} as failed"
                    ),
                    style="yellow",
                    title="🔍 Dry Run Results",
                )
            )
            return

        # Show processing animation
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=True,
        ) as progress:

            task = progress.add_task(
                "🔧 Marking scans as failed...", total=len(stuck_scans)
            )
            failed_count = 0

            with transaction.atomic():
                for i, stuck_scan in enumerate(stuck_scans):
                    scan = stuck_scan["scan"]
                    task_result = stuck_scan["task_result"]

                    progress.update(
                        task,
                        advance=1,
                        description=f"🔧 Processing scan {i + 1}/{len(stuck_scans)}",
                    )

                    try:
                        # Update scan state to FAILED using admin connection
                        scan.state = StateChoices.FAILED
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.save(
                            using=MainRouter.admin_db,
                            update_fields=["state", "completed_at"],
                        )

                        task_result.status = "FAILURE"
                        task_result.result = json.dumps(
                            {
                                "exc_type": "ScanStuckError",
                                "exc_message": [
                                    "Scan was detected as stuck and marked as failed."
                                ],
                            }
                        )
                        task_result.date_done = datetime.now(timezone.utc)
                        task_result.save(using=MainRouter.admin_db)

                        failed_count += 1
                        if self.logger and hasattr(self.logger, "info"):
                            self.logger.info(
                                f"Marked scan {scan.id} (tenant: {scan.tenant_id}) as failed"
                            )

                    except Exception as e:
                        if self.logger and hasattr(self.logger, "error"):
                            self.logger.error(f"Failed to update scan {scan.id}: {e}")

                    time.sleep(0.2)  # Small delay for visual effect

                progress.update(
                    task,
                    description=f"✅ Completed - {failed_count} scans marked as failed",
                )
                time.sleep(0.5)

        # Show final results
        self.console.print("\n")
        if failed_count > 0:
            self.console.print(
                Panel(
                    Align.center(
                        f"🎉 Successfully marked {failed_count} scan{'s' if failed_count != 1 else ''} as failed"
                    ),
                    style="green",
                    title="✅ Task Complete",
                )
            )

            # Show summary table
            self.show_summary_table(stuck_scans, failed_count)
        else:
            self.console.print(
                Panel(
                    Align.center("⚠️ No scans were updated"),
                    style="yellow",
                    title="⚠️ Warning",
                )
            )

    def show_summary_table(self, processed_scans: List[Dict], success_count: int):
        """Show a summary table of processed scans"""
        if success_count == 0:
            return

        self.console.print("\n")

        # Create summary table
        table = Table(
            title=f"📋 Summary - {success_count} Scan{'s' if success_count != 1 else ''} Marked as Failed",
            show_header=True,
            header_style="bold white",
            title_style="bold green",
            border_style="green",
        )

        table.add_column("🆔 Scan ID", style="cyan", no_wrap=True)
        table.add_column("🏢 Tenant", style="bright_blue", no_wrap=True)
        table.add_column("☁️ Provider", style="green", no_wrap=True)
        table.add_column("⏰ Started At", style="yellow")
        table.add_column("📝 Scan Name", style="blue")

        for scan_data in processed_scans:
            scan = scan_data["scan"]

            # Show full IDs since we have no_wrap=True
            scan_id_full = str(scan.id)
            tenant_id_full = str(scan.tenant_id) if scan.tenant_id else "Unknown"

            # Format provider info with full details
            provider_info = f"{scan.provider.provider.upper()}: {scan.provider.uid}"

            # Format start time
            started_time = (
                scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.started_at
                else "Unknown"
            )

            # Get scan name
            scan_name = scan.name or "N/A"

            table.add_row(
                scan_id_full, tenant_id_full, provider_info, started_time, scan_name
            )

        self.console.print(table)

        # Add helpful note
        self.console.print("\n")
        self.console.print(
            Panel(
                "💡 These scans were stuck (executing but no active task in workers) and have been marked as failed.\n"
                "You can now retry them from the Prowler interface.",
                style="dim",
                title="ℹ️ Note",
                border_style="dim",
            )
        )

    def handle(self, *args, **options):
        force = options["force"]
        dry_run = options["dry_run"]
        verbose = options["verbose"]

        # Setup logging based on verbose flag
        self.setup_logging(verbose)

        # Clear screen and show header
        self.console.clear()
        self.console.print(
            Panel.fit("🔍 Prowler Stuck Scans Checker", style="bold blue")
        )

        if self.logger and hasattr(self.logger, "info"):
            self.logger.info("Starting stuck scans check across all tenants...")

        try:
            # Find stuck scans with interactive progress
            stuck_scans = self.find_stuck_scans()

            # Display results interactively
            scans_to_process = self.display_stuck_scans(stuck_scans, force)

            if not scans_to_process:
                if stuck_scans and not force:
                    # User didn't confirm any scans
                    self.console.print("\n")
                    self.console.print(
                        Panel(
                            Align.center("🚫 No scans selected for processing"),
                            style="yellow",
                            title="❌ Operation Cancelled",
                        )
                    )
                return

            # Mark confirmed scans as failed
            self.mark_scans_as_failed(scans_to_process, dry_run)

        except KeyboardInterrupt:
            self.console.print("\n")
            self.console.print(
                Panel(
                    Align.center("🛑 Operation cancelled by user"),
                    style="red",
                    title="❌ Interrupted",
                )
            )
            return
        except Exception as e:
            if self.logger and hasattr(self.logger, "error"):
                self.logger.error(f"Error during stuck scans check: {e}")
            self.console.print("\n")
            self.console.print(
                Panel(
                    Align.center(f"💥 Error: {str(e)}"),
                    style="red",
                    title="❌ Command Failed",
                )
            )
            raise CommandError(f"Command failed: {e}")

        if self.logger and hasattr(self.logger, "info"):
            self.logger.info("Stuck scans check completed successfully")
