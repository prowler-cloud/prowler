from datetime import datetime, timezone
from uuid import uuid4

import pytest
from dateutil.relativedelta import relativedelta
from uuid6 import UUID

from api.uuid_utils import (
    datetime_to_uuid7,
    datetime_from_uuid7,
    uuid7_start,
    uuid7_end,
    uuid7_range,
    parse_params_to_uuid7,
)


def test_parse_params_to_uuid7():
    uuid = parse_params_to_uuid7("0191dff4-7a78-7031-8814-4fb51bf2bd5b")
    assert isinstance(uuid, UUID)

    uuids = parse_params_to_uuid7(
        ["0191dff4-7a78-7031-8814-4fb51bf2bd5b", "01856aa0-c800-7b8f-bfa0-46a393f14d50"]
    )
    assert isinstance(uuids, list)
    assert len(uuids) == 2

    uuids = parse_params_to_uuid7(
        "0191dff4-7a78-7031-8814-4fb51bf2bd5b,01856aa0-c800-7b8f-bfa0-46a393f14d50"
    )
    assert isinstance(uuids, list)
    assert len(uuids) == 2


@pytest.mark.parametrize(
    "input_datetime",
    [
        datetime(2024, 9, 11, 7, 20, 27, tzinfo=timezone.utc),
        datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    ],
)
def test_timestamp_to_uuid7(input_datetime):
    uuid7 = datetime_to_uuid7(input_datetime)
    # assert instance is all we can do without reversing the math in the test
    assert isinstance(uuid7, UUID)
    assert uuid7.version == 7
    assert uuid7.time == int(input_datetime.timestamp() * 1000)


@pytest.mark.parametrize(
    "uuid7, expected_datetime",
    [
        (
            "0191dff4-7a78-7031-8814-4fb51bf2bd5b",
            datetime(2024, 9, 11, 7, 20, 27, tzinfo=timezone.utc),
        ),
        (
            "01856aa0-c800-7b8f-bfa0-46a393f14d50",
            datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        ),
    ],
)
def test_datetime_from_uuid7(uuid7, expected_datetime):
    extracted_datetime = datetime_from_uuid7(uuid7=UUID(uuid7))
    assert extracted_datetime == expected_datetime


def test_extract_timestamp_from_uuid4_invalid():
    with pytest.raises(ValueError):
        datetime_from_uuid7(uuid4())


def test_uuid7_start():
    dt = datetime.now(timezone.utc)
    uuid = datetime_to_uuid7(dt)
    dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    start = uuid7_start(uuid)
    expected_ts = (
        int(dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()) * 1000
    )
    assert start.time == expected_ts


@pytest.mark.parametrize(
    "days_offset",
    [0, 1, 10, 30, 60],
)
def test_uuid7_end(days_offset):
    dt = datetime.now(timezone.utc)
    uuid = datetime_to_uuid7(dt)

    end = uuid7_end(uuid, days_offset)

    dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    dt = dt + relativedelta(days=days_offset + 1, microseconds=-1)
    expected_ts = int(dt.timestamp()) * 1000

    assert end.time == expected_ts


def test_uuid7_range():
    uuids = [
        datetime_to_uuid7(datetime.now(timezone.utc)),
        datetime_to_uuid7(datetime.now(timezone.utc).replace(year=2023)),
        datetime_to_uuid7(datetime.now(timezone.utc).replace(year=2024)),
        datetime_to_uuid7(datetime.now(timezone.utc).replace(year=2025)),
    ]
    expected_start = (
        int(
            datetime.fromtimestamp(uuids[1].time / 1000, tz=timezone.utc)
            .replace(hour=0, minute=0, second=0, microsecond=0)
            .timestamp()
        )
        * 1000
    )
    expected_end = (
        int(
            datetime.fromtimestamp(uuids[-1].time / 1000, tz=timezone.utc)
            .replace(hour=23, minute=59, second=59, microsecond=999999)
            .timestamp()
        )
        * 1000
    )

    start, end = uuid7_range(uuids)

    assert start.time == expected_start
    assert end.time == expected_end
