import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
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
    def __init__(self, element_id: str, start: str, end: str, rel_type: str, properties: dict):
        self.element_id = element_id
        self.type = rel_type
        self.start_node = SimpleNamespace(element_id=start)
        self.end_node = SimpleNamespace(element_id=end)
        self._properties = properties

    def items(self):
        return self._properties.items()


@pytest.mark.django_db
class TestAttackPaths:
    def test_attack_paths_scans_list_returns_latest_per_provider(
        self, authenticated_client, providers_fixture
    ):
        provider_one, provider_two, *_ = providers_fixture
        now = timezone.now()

        AttackPathsScan.objects.create(
            tenant_id=provider_one.tenant_id,
            provider=provider_one,
            state=StateChoices.COMPLETED,
            progress=100,
            started_at=now - timedelta(hours=3),
            completed_at=now - timedelta(hours=2),
        )
        most_recent = AttackPathsScan.objects.create(
            tenant_id=provider_one.tenant_id,
            provider=provider_one,
            state=StateChoices.EXECUTING,
            progress=45,
            started_at=now - timedelta(minutes=15),
        )
        other_provider_scan = AttackPathsScan.objects.create(
            tenant_id=provider_two.tenant_id,
            provider=provider_two,
            state=StateChoices.COMPLETED,
            progress=100,
            started_at=now - timedelta(hours=2),
            completed_at=now - timedelta(hours=1),
        )

        response = authenticated_client.get(reverse("attack-paths-scans-list"))
        assert response.status_code == 200

        payload = response.json()
        data = payload["data"]
        assert len(data) == 2
        assert data[0]["id"] == str(most_recent.id)
        assert {item["id"] for item in data} == {
            str(most_recent.id),
            str(other_provider_scan.id),
        }

    def test_attack_paths_scan_attack_path_queries_returns_definitions(
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
            reverse("attack-paths-queries", kwargs={"pk": scan.id})
        )
        assert response.status_code == 200

        payload = response.json()
        data = payload["data"]
        assert len(data) >= 1
        first_query = data[0]
        assert first_query["type"] == "attack-path-queries"
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
                "type": "attack-path-query-runs",
                "attributes": {
                    "id": "aws-ec2-instance-security-groups",
                    "parameters": {"instance_id": "i-1234567890"},
                },
            }
        }

        response = authenticated_client.post(
            reverse("attack-paths-run-query", kwargs={"pk": scan.id}),
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
                    "type": "attack-path-query-runs",
                    "attributes": {
                        "id": "aws-ec2-instance-security-groups",
                        "parameters": {"instance_id": "i-01"},
                    },
                }
            }

            response = authenticated_client.post(
                reverse(
                    "attack-paths-run-query", kwargs={"pk": scan.id}
                ),
                data=json.dumps(payload),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["type"] == "attack-path-query-results"
        attributes = body["data"]["attributes"]
        assert len(attributes["nodes"]) == 1
        assert len(attributes["relationships"]) == 1
        assert attributes["nodes"][0]["properties"]["id"] == "i-01"
