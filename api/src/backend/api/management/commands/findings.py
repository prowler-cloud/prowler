import random
from datetime import datetime, timezone
from math import ceil
from uuid import uuid4

from django.core.management.base import BaseCommand
from tqdm import tqdm

from api.db_utils import rls_transaction
from api.models import (
    FilterValue,
    Finding,
    Provider,
    Resource,
    ResourceFindingMapping,
    Scan,
    StatusChoices,
)
from prowler.lib.check.models import CheckMetadata


class Command(BaseCommand):
    help = "Populates the database with test data for performance testing."

    def add_arguments(self, parser):
        parser.add_argument(
            "--tenant",
            type=str,
            required=True,
            help="Tenant id for which the data will be populated.",
        )
        parser.add_argument(
            "--resources",
            type=int,
            required=True,
            help="The number of resources to create.",
        )
        parser.add_argument(
            "--findings",
            type=int,
            required=True,
            help="The number of findings to create.",
        )
        parser.add_argument(
            "--batch", type=int, required=True, help="The batch size for bulk creation."
        )
        parser.add_argument(
            "--alias",
            type=str,
            required=False,
            help="Optional alias for the provider and scan",
        )

    def handle(self, *args, **options):
        tenant_id = options["tenant"]
        num_resources = options["resources"]
        num_findings = options["findings"]
        batch_size = options["batch"]
        alias = options["alias"] or "Testing"
        uid_token = str(uuid4())

        self.stdout.write(self.style.NOTICE("Starting data population"))
        self.stdout.write(self.style.NOTICE(f"\tTenant: {tenant_id}"))
        self.stdout.write(self.style.NOTICE(f"\tAlias: {alias}"))
        self.stdout.write(self.style.NOTICE(f"\tResources: {num_resources}"))
        self.stdout.write(self.style.NOTICE(f"\tFindings: {num_findings}"))
        self.stdout.write(self.style.NOTICE(f"\tBatch size: {batch_size}\n\n"))

        # Resource metadata
        possible_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "ca-central-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-south-1",
            "sa-east-1",
        ]
        possible_services = []
        possible_types = []

        bulk_check_metadata = CheckMetadata.get_bulk(provider="aws")
        for check_metadata in bulk_check_metadata.values():
            if check_metadata.ServiceName not in possible_services:
                possible_services.append(check_metadata.ServiceName)
            if (
                check_metadata.ResourceType
                and check_metadata.ResourceType not in possible_types
            ):
                possible_types.append(check_metadata.ResourceType)

        with rls_transaction(tenant_id):
            provider, _ = Provider.all_objects.get_or_create(
                tenant_id=tenant_id,
                provider="aws",
                connected=True,
                uid=str(random.randint(100000000000, 999999999999)),
                defaults={
                    "alias": alias,
                },
            )

        with rls_transaction(tenant_id):
            scan = Scan.all_objects.create(
                tenant_id=tenant_id,
                provider=provider,
                name=alias,
                trigger="manual",
                state="executing",
                progress=0,
                started_at=datetime.now(timezone.utc),
            )
        scan_state = "completed"

        try:
            # Create resources
            resources = []

            for i in range(num_resources):
                resources.append(
                    Resource(
                        tenant_id=tenant_id,
                        provider_id=provider.id,
                        uid=f"testing-{uid_token}-{i}",
                        name=f"Testing {uid_token}-{i}",
                        region=random.choice(possible_regions),
                        service=random.choice(possible_services),
                        type=random.choice(possible_types),
                    )
                )

            num_batches = ceil(len(resources) / batch_size)
            self.stdout.write(self.style.WARNING("Creating resources..."))
            for i in tqdm(range(0, len(resources), batch_size), total=num_batches):
                with rls_transaction(tenant_id):
                    Resource.all_objects.bulk_create(resources[i : i + batch_size])
            self.stdout.write(self.style.SUCCESS("Resources created successfully.\n\n"))

            with rls_transaction(tenant_id):
                scan.progress = 33
                scan.save()

            # Create Findings
            findings = []
            possible_deltas = ["new", "changed", None]
            possible_severities = ["critical", "high", "medium", "low"]
            findings_resources_mapping = []

            for i in range(num_findings):
                severity = random.choice(possible_severities)
                check_id = random.randint(1, 1000)
                assigned_resource_num = random.randint(0, len(resources) - 1)
                assigned_resource = resources[assigned_resource_num]
                findings_resources_mapping.append(assigned_resource_num)

                findings.append(
                    Finding(
                        tenant_id=tenant_id,
                        scan=scan,
                        uid=f"testing-{uid_token}-{i}",
                        delta=random.choice(possible_deltas),
                        check_id=f"check-{check_id}",
                        status=random.choice(list(StatusChoices)),
                        severity=severity,
                        impact=severity,
                        raw_result={},
                        check_metadata={
                            "checktitle": f"Test title for check {check_id}",
                            "risk": f"Testing risk {uid_token}-{i}",
                            "provider": "aws",
                            "severity": severity,
                            "categories": ["category1", "category2", "category3"],
                            "description": "This is a random description that should not matter for testing purposes.",
                            "servicename": assigned_resource.service,
                            "resourcetype": assigned_resource.type,
                        },
                    )
                )

            num_batches = ceil(len(findings) / batch_size)
            self.stdout.write(self.style.WARNING("Creating findings..."))
            for i in tqdm(range(0, len(findings), batch_size), total=num_batches):
                with rls_transaction(tenant_id):
                    Finding.all_objects.bulk_create(findings[i : i + batch_size])
            self.stdout.write(self.style.SUCCESS("Findings created successfully.\n\n"))

            with rls_transaction(tenant_id):
                scan.progress = 66
                scan.save()

            # Create ResourceFindingMapping
            mappings = []
            filter_cache: set[tuple] = set()
            for index, finding_instance in enumerate(findings):
                resource_instance = resources[findings_resources_mapping[index]]
                mappings.append(
                    ResourceFindingMapping(
                        tenant_id=tenant_id,
                        resource=resource_instance,
                        finding=finding_instance,
                    )
                )
                dimensions = [
                    ("service", resource_instance.service),
                    ("region", resource_instance.region),
                    ("resource_type", resource_instance.type),
                    ("status", finding_instance.status),
                    ("severity", finding_instance.severity),
                    ("provider_type", provider.provider),
                    ("delta", finding_instance.delta),
                ]

                for dimension, value in dimensions:
                    if value is not None:
                        filter_cache.add((str(resource_instance.id), dimension, value))

            num_batches = ceil(len(mappings) / batch_size)
            self.stdout.write(
                self.style.WARNING("Creating resource-finding mappings...")
            )
            for i in tqdm(range(0, len(mappings), batch_size), total=num_batches):
                with rls_transaction(tenant_id):
                    ResourceFindingMapping.objects.bulk_create(
                        mappings[i : i + batch_size]
                    )
            self.stdout.write(
                self.style.SUCCESS(
                    "Resource-finding mappings created successfully.\n\n"
                )
            )

            with rls_transaction(tenant_id):
                scan.progress = 99
                scan.save()

            self.stdout.write(self.style.WARNING("Creating finding filter values..."))
            filter_values = [
                FilterValue(
                    tenant_id=tenant_id,
                    scan_id=str(scan.id),
                    resource_id=resource_id,
                    dimension=dimension,
                    value=value,
                )
                for resource_id, dimension, value in filter_cache
            ]
            num_batches = ceil(len(filter_values) / batch_size)
            with rls_transaction(tenant_id):
                for i in tqdm(
                    range(0, len(filter_values), batch_size), total=num_batches
                ):
                    with rls_transaction(tenant_id):
                        FilterValue.objects.bulk_create(
                            filter_values[i : i + batch_size], ignore_conflicts=True
                        )

            self.stdout.write(
                self.style.SUCCESS("Finding filter values created successfully.\n\n")
            )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to populate test data: {e}"))
            scan_state = "failed"
        finally:
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration = int(
                (datetime.now(timezone.utc) - scan.started_at).total_seconds()
            )
            scan.progress = 100
            scan.state = scan_state
            scan.unique_resource_count = num_resources
            with rls_transaction(tenant_id):
                scan.save()

        self.stdout.write(self.style.NOTICE("Successfully populated test data."))
