from unittest import mock

from prowler.providers.aws.services.appstream.appstream_service import Fleet
from tests.providers.aws.audit_info_utils import AWS_REGION_EU_WEST_1


class Test_appstream_fleet_session_disconnect_timeout:
    def test_no_fleets(self):
        appstream_client = mock.MagicMock
        appstream_client.fleets = []
        with mock.patch(
            "prowler.providers.aws.services.appstream.appstream_service.AppStream",
            new=appstream_client,
        ):
            # Test Check
            from prowler.providers.aws.services.appstream.appstream_fleet_session_disconnect_timeout.appstream_fleet_session_disconnect_timeout import (
                appstream_fleet_session_disconnect_timeout,
            )

            check = appstream_fleet_session_disconnect_timeout()
            result = check.execute()

            assert len(result) == 0

    def test_one_fleet_session_disconnect_timeout_more_than_5_minutes(self):
        appstream_client = mock.MagicMock
        appstream_client.fleets = []
        fleet1 = Fleet(
            arn="arn",
            name="test-fleet",
            max_user_duration_in_seconds=1 * 60 * 60,
            # 1 hour
            disconnect_timeout_in_seconds=1 * 60 * 60,
            idle_disconnect_timeout_in_seconds=900,
            enable_default_internet_access=True,
            region=AWS_REGION_EU_WEST_1,
        )

        appstream_client.fleets.append(fleet1)
        appstream_client.audit_config = {"max_disconnect_timeout_in_seconds": 300}

        with mock.patch(
            "prowler.providers.aws.services.appstream.appstream_service.AppStream",
            new=appstream_client,
        ):
            # Test Check
            from prowler.providers.aws.services.appstream.appstream_fleet_session_disconnect_timeout.appstream_fleet_session_disconnect_timeout import (
                appstream_fleet_session_disconnect_timeout,
            )

            check = appstream_fleet_session_disconnect_timeout()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_arn == fleet1.arn
            assert result[0].region == fleet1.region
            assert result[0].resource_id == fleet1.name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Fleet {fleet1.name} has the session disconnect timeout set to more than 5 minutes."
            )
            assert result[0].resource_tags == []

    def test_one_fleet_session_disconnect_timeout_less_than_5_minutes(self):
        appstream_client = mock.MagicMock
        appstream_client.fleets = []
        fleet1 = Fleet(
            arn="arn",
            name="test-fleet",
            max_user_duration_in_seconds=900,
            # 4 minutes
            disconnect_timeout_in_seconds=4 * 60,
            idle_disconnect_timeout_in_seconds=900,
            enable_default_internet_access=True,
            region=AWS_REGION_EU_WEST_1,
        )

        appstream_client.fleets.append(fleet1)

        appstream_client.audit_config = {"max_disconnect_timeout_in_seconds": 300}

        with mock.patch(
            "prowler.providers.aws.services.appstream.appstream_service.AppStream",
            new=appstream_client,
        ):
            # Test Check
            from prowler.providers.aws.services.appstream.appstream_fleet_session_disconnect_timeout.appstream_fleet_session_disconnect_timeout import (
                appstream_fleet_session_disconnect_timeout,
            )

            check = appstream_fleet_session_disconnect_timeout()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_arn == fleet1.arn
            assert result[0].region == fleet1.region
            assert result[0].resource_id == fleet1.name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Fleet {fleet1.name} has the session disconnect timeout set to less than 5 minutes."
            )
            assert result[0].resource_tags == []

    def test_two_fleets_session_disconnect_timeout_less_than_5_minutes_one_more_than_5_minutes(
        self,
    ):
        appstream_client = mock.MagicMock
        appstream_client.fleets = []
        fleet1 = Fleet(
            arn="arn",
            name="test-fleet-1",
            max_user_duration_in_seconds=1 * 60 * 60,
            # 1 Hours
            disconnect_timeout_in_seconds=1 * 60 * 60,
            idle_disconnect_timeout_in_seconds=900,
            enable_default_internet_access=True,
            region=AWS_REGION_EU_WEST_1,
        )
        fleet2 = Fleet(
            arn="arn",
            name="test-fleet-2",
            max_user_duration_in_seconds=24 * 60 * 60,
            #  3 minutes
            disconnect_timeout_in_seconds=3 * 60,
            idle_disconnect_timeout_in_seconds=900,
            enable_default_internet_access=False,
            region=AWS_REGION_EU_WEST_1,
        )

        appstream_client.fleets.append(fleet1)
        appstream_client.fleets.append(fleet2)

        appstream_client.audit_config = {"max_disconnect_timeout_in_seconds": 300}

        with mock.patch(
            "prowler.providers.aws.services.appstream.appstream_service.AppStream",
            new=appstream_client,
        ):
            # Test Check
            from prowler.providers.aws.services.appstream.appstream_fleet_session_disconnect_timeout.appstream_fleet_session_disconnect_timeout import (
                appstream_fleet_session_disconnect_timeout,
            )

            check = appstream_fleet_session_disconnect_timeout()
            result = check.execute()

            assert len(result) == 2

            for res in result:
                if res.resource_id == fleet1.name:
                    assert result[0].resource_arn == fleet1.arn
                    assert result[0].region == fleet1.region
                    assert result[0].resource_id == fleet1.name
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Fleet {fleet1.name} has the session disconnect timeout set to more than 5 minutes."
                    )
                    assert result[0].resource_tags == []
                if res.resource_id == fleet2.name:
                    assert result[1].resource_arn == fleet2.arn
                    assert result[1].region == fleet2.region
                    assert result[1].resource_id == fleet2.name
                    assert result[1].status == "PASS"
                    assert (
                        result[1].status_extended
                        == f"Fleet {fleet2.name} has the session disconnect timeout set to less than 5 minutes."
                    )
                    assert result[1].resource_tags == []
