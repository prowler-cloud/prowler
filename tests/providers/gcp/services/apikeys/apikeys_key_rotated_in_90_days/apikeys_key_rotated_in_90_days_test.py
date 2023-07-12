from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_apikeys_key_rotated_in_90_days:
    def test_apikeys_no_keys(self):
        apikeys_client = mock.MagicMock
        apikeys_client.keys = []

        with mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days import (
                apikeys_key_rotated_in_90_days,
            )

            check = apikeys_key_rotated_in_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_key(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2023-06-01T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days import (
                apikeys_key_rotated_in_90_days,
            )

            check = apikeys_key_rotated_in_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"API key {key.name} created in less than 90 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_one_key_with_more_than_90_days(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2022-06-05T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_key_rotated_in_90_days.apikeys_key_rotated_in_90_days import (
                apikeys_key_rotated_in_90_days,
            )

            check = apikeys_key_rotated_in_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"API key {key.name} creation date has more than 90 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id
