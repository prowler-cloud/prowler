import datetime

from freezegun import freeze_time


def test_freezegun_handles_lazy_okta_models_and_restores_datetime():
    import okta.client  # noqa: F401

    real_datetime_id = id(datetime.datetime)

    with freeze_time("2025-01-01 00:00:00"):
        from okta.models import NetworkZoneAddress

        assert NetworkZoneAddress.__name__ == "NetworkZoneAddress"
        assert datetime.datetime.now() == datetime.datetime(2025, 1, 1)

    assert id(datetime.datetime) == real_datetime_id
