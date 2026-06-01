from django.core.management.base import BaseCommand

from tasks.jobs.orphan_recovery import reconcile_orphans


class Command(BaseCommand):
    help = (
        "Recover orphaned Celery tasks: re-enqueue work whose worker is gone and "
        "mark stale task results terminal. Single-flight via a Postgres advisory lock."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--grace-minutes",
            type=int,
            default=2,
            help="Skip tasks started within this window (worker may still register).",
        )
        parser.add_argument(
            "--max-attempts",
            type=int,
            default=3,
            help="Give up re-running a task after this many recovery attempts (scans are marked FAILED).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Detect and report orphans without revoking or re-enqueuing.",
        )

    def handle(self, *args, **options):
        result = reconcile_orphans(
            grace_minutes=options["grace_minutes"],
            max_attempts=options["max_attempts"],
            dry_run=options["dry_run"],
        )

        if not result.get("acquired"):
            self.stdout.write("Reconcile skipped: another run holds the lock.")
            return

        self.stdout.write(
            self.style.SUCCESS(
                "Orphan reconcile complete: "
                f"recovered={len(result.get('recovered', []))} "
                f"failed={len(result.get('failed', []))} "
                f"skipped(in-flight)={len(result.get('skipped', []))}"
            )
        )
