"""``python manage.py list_neo4j_tenant_dbs``

Prints every ``db-tenant-*`` database still living on Neo4j. Phase 2 of the
Neptune migration can ship once this command returns zero rows across every
Neptune-configured environment.

# TODO: Drop after Neptune migration is finished
"""
from django.core.management.base import BaseCommand

from tasks.jobs.attack_paths.legacy_ops import list_neo4j_tenant_databases


class Command(BaseCommand):
    help = "List legacy Neo4j tenant databases (db-tenant-*) still present on the cluster"

    def handle(self, *args, **options) -> None:
        names = list_neo4j_tenant_databases()
        if not names:
            self.stdout.write(self.style.SUCCESS("No legacy Neo4j tenant DBs remain."))
            return

        self.stdout.write(self.style.WARNING(f"{len(names)} legacy Neo4j tenant DBs:"))
        for name in names:
            self.stdout.write(f"  - {name}")
