from datetime import datetime, timezone
from uuid import uuid4

import pytest
from dateutil.relativedelta import relativedelta
from rest_framework_json_api.serializers import ValidationError
from uuid6 import UUID

from api.uuid_utils import (
    transform_into_uuid7,
    datetime_to_uuid7,
    datetime_from_uuid7,
    uuid7_start,
    uuid7_end,
    uuid7_range,
)


def test_transform_into_uuid7_valid():
    uuid_v7 = datetime_to_uuid7(datetime.now(timezone.utc))
    transformed_uuid = transform_into_uuid7(uuid_v7)
    assert transformed_uuid == UUID(hex=uuid_v7.hex.upper())
    assert transformed_uuid.version == 7


def test_transform_into_uuid7_invalid_version():
    uuid_v4 = uuid4()
    with pytest.raises(ValidationError) as exc_info:
        transform_into_uuid7(UUID(str(uuid_v4)))
    assert str(exc_info.value.detail[0]) == "Invalid UUIDv7 value."


@pytest.mark.parametrize(
    "input_datetime",
    [
        datetime(2024, 9, 11, 7, 20, 27, tzinfo=timezone.utc),
        datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    ],
)
def test_datetime_to_uuid7(input_datetime):
    uuid7 = datetime_to_uuid7(input_datetime)
    assert isinstance(uuid7, UUID)
    assert uuid7.version == 7
    expected_timestamp_ms = int(input_datetime.timestamp() * 1000) & 0xFFFFFFFFFFFF
    assert uuid7.time == expected_timestamp_ms


@pytest.mark.parametrize(
    "input_datetime",
    [
        datetime(2024, 9, 11, 7, 20, 27, tzinfo=timezone.utc),
        datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    ],
)
def test_datetime_from_uuid7(input_datetime):
    uuid7 = datetime_to_uuid7(input_datetime)
    extracted_datetime = datetime_from_uuid7(uuid7)
    assert extracted_datetime == input_datetime


def test_datetime_from_uuid7_invalid():
    uuid_v4 = uuid4()
    with pytest.raises(ValueError):
        datetime_from_uuid7(UUID(str(uuid_v4)))


def test_uuid7_start():
    dt = datetime.now(timezone.utc)
    uuid = datetime_to_uuid7(dt)
    start_uuid = uuid7_start(uuid)
    expected_dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    expected_timestamp_ms = int(expected_dt.timestamp() * 1000) & 0xFFFFFFFFFFFF
    assert start_uuid.time == expected_timestamp_ms
    assert start_uuid.version == 7


@pytest.mark.parametrize("months_offset", [0, 1, 10, 30, 60])
def test_uuid7_end(months_offset):
    dt = datetime.now(timezone.utc)
    uuid = datetime_to_uuid7(dt)
    end_uuid = uuid7_end(uuid, months_offset)
    expected_dt = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    expected_dt += relativedelta(months=months_offset, microseconds=-1)
    expected_timestamp_ms = int(expected_dt.timestamp() * 1000) & 0xFFFFFFFFFFFF
    assert end_uuid.time == expected_timestamp_ms
    assert end_uuid.version == 7


def test_uuid7_range():
    dt_now = datetime.now(timezone.utc)
    uuid_list = [
        datetime_to_uuid7(dt_now),
        datetime_to_uuid7(dt_now.replace(year=2023)),
        datetime_to_uuid7(dt_now.replace(year=2024)),
        datetime_to_uuid7(dt_now.replace(year=2025)),
    ]
    start_uuid, end_uuid = uuid7_range(uuid_list)

    # Expected start of range
    start_dt = datetime_from_uuid7(min(uuid_list, key=lambda u: u.time))
    start_dt = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    expected_start_timestamp_ms = int(start_dt.timestamp() * 1000) & 0xFFFFFFFFFFFF

    # Expected end of range
    end_dt = datetime_from_uuid7(max(uuid_list, key=lambda u: u.time))
    end_dt = end_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end_dt += relativedelta(months=1, microseconds=-1)
    expected_end_timestamp_ms = int(end_dt.timestamp() * 1000) & 0xFFFFFFFFFFFF

    assert start_uuid.time == expected_start_timestamp_ms
    assert end_uuid.time == expected_end_timestamp_ms
    assert start_uuid.version == 7
    assert end_uuid.version == 7
