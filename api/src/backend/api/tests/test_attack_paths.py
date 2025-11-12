import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from api.models import AttackPathsScan, StateChoices
from conftest import API_JSON_CONTENT_TYPE


class FakeNode:
    def __init__(self, element_id: str, labels: list[str], properties: dict):
        self.element_id = element_id
        self.labels = set(labels)
        self._properties = properties

    def items(self):
        return self._properties.items()


class FakeRelationship:
    def __init__(
        self, element_id: str, start: str, end: str, rel_type: str, properties: dict
    ):
        self.element_id = element_id
        self.type = rel_type
        self.start_node = SimpleNamespace(element_id=start)
        self.end_node = SimpleNamespace(element_id=end)
        self._properties = properties

    def items(self):
        return self._properties.items()


@pytest.mark.django_db
class TestAttackPaths:
    def test_attack_paths_scans_list_is_paginated_and_ordered(
        self, authenticated_client, providers_fixture
    ):
        provider, *_ = providers_fixture
        tenant_id = provider.tenant_id
        page_size = settings.REST_FRAMEWORK["PAGE_SIZE"]

        AttackPathsScan.objects.filter(tenant_id=tenant_id).delete()

        total_to_create = page_size + 1
        base_time = timezone.now() - timedelta(minutes=total_to_create + 5)
        created_scans: list[AttackPathsScan] = []

        for index in range(total_to_create):
            scan = AttackPathsScan.objects.create(
                tenant_id=tenant_id,
                provider=provider,
                state=StateChoices.COMPLETED,
                progress=50 + index,
                started_at=base_time + timedelta(minutes=index),
                completed_at=base_time + timedelta(minutes=index + 1),
            )
            AttackPathsScan.objects.filter(pk=scan.pk).update(
                inserted_at=base_time + timedelta(minutes=index)
            )
            scan.refresh_from_db()
            created_scans.append(scan)

        total_scans = AttackPathsScan.objects.filter(tenant_id=tenant_id).count()
        latest_scan = max(created_scans, key=lambda s: s.inserted_at)

        paginated_response = authenticated_client.get(
            reverse("attack-paths-scans-list")
        )
        assert paginated_response.status_code == 200

        paginated_payload = paginated_response.json()
        paginated_data = paginated_payload["data"]
        assert len(paginated_data) == min(page_size, total_scans)
        assert paginated_data[0]["id"] == str(latest_scan.id)
        paginated_meta = paginated_payload.get("meta", {})
        assert "pagination" in paginated_meta
        assert paginated_meta["pagination"]["count"] == total_scans

        unpaginated_response = authenticated_client.get(
            reverse("attack-paths-scans-list"), {"page[disable]": "true"}
        )
        assert unpaginated_response.status_code == 200
        unpaginated_payload = unpaginated_response.json()
        unpaginated_data = unpaginated_payload["data"]
        assert len(unpaginated_data) == total_scans
        unpaginated_meta = unpaginated_payload.get("meta", {})
        assert "pagination" not in unpaginated_meta

    def test_attack_paths_queries_returns_definitions(
        self, authenticated_client, providers_fixture
    ):
        provider, *_ = providers_fixture
        scan = AttackPathsScan.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            state=StateChoices.COMPLETED,
            progress=100,
            started_at=timezone.now() - timedelta(hours=1),
            completed_at=timezone.now() - timedelta(minutes=5),
            neo4j_database="tenant-db",
        )

        response = authenticated_client.get(
            reverse("attack-paths-scans-queries", kwargs={"pk": scan.id})
        )
        assert response.status_code == 200

        payload = response.json()
        data = payload["data"]
        assert len(data) >= 1
        first_query = data[0]
        assert first_query["type"] == "attack-paths-queries"
        assert "attributes" in first_query
        assert first_query["attributes"]["provider"] == provider.provider

    def test_attack_paths_scan_run_requires_completed_state(
        self, authenticated_client, providers_fixture
    ):
        provider, *_ = providers_fixture
        scan = AttackPathsScan.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            state=StateChoices.EXECUTING,
            progress=70,
            started_at=timezone.now() - timedelta(minutes=10),
            neo4j_database="tenant-db",
        )

        payload = {
            "data": {
                "type": "attack-paths-scans-queries-runs",
                "attributes": {
                    "id": "aws-ec2-instance-security-groups",
                    "parameters": {"instance_id": "i-1234567890"},
                },
            }
        }

        response = authenticated_client.post(
            reverse("attack-paths-scans-queries-run", kwargs={"pk": scan.id}),
            data=json.dumps(payload),
            content_type=API_JSON_CONTENT_TYPE,
        )

        assert response.status_code == 400
        assert "detail" in response.json()

    def test_attack_paths_scan_run_success(
        self, authenticated_client, providers_fixture
    ):
        provider, *_ = providers_fixture
        scan = AttackPathsScan.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            state=StateChoices.COMPLETED,
            progress=100,
            started_at=timezone.now() - timedelta(hours=1),
            completed_at=timezone.now() - timedelta(minutes=2),
            neo4j_database="tenant-db",
        )

        nodes = [FakeNode("1", ["AwsEc2Instance"], {"id": "i-01"})]
        relationships = [
            FakeRelationship("2", "1", "3", "MEMBER_OF_SECURITY_GROUP", {}),
        ]

        mock_result = [{"nodes": nodes, "relationships": relationships}]

        with patch("api.v1.views.neo4j.get_neo4j_session") as mocked_session:
            context_manager = mocked_session.return_value
            session = context_manager.__enter__.return_value
            session.run.return_value = mock_result

            payload = {
                "data": {
                    "type": "attack-paths-scans-queries-runs",
                    "attributes": {
                        "id": "aws-ec2-instance-security-groups",
                        "parameters": {"instance_id": "i-01"},
                    },
                }
            }

            response = authenticated_client.post(
                reverse("attack-paths-scans-queries-run", kwargs={"pk": scan.id}),
                data=json.dumps(payload),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["type"] == "attack-paths-scans-queries-results"
        attributes = body["data"]["attributes"]
        assert len(attributes["nodes"]) == 1
        assert len(attributes["relationships"]) == 1
        assert attributes["nodes"][0]["properties"]["id"] == "i-01"
