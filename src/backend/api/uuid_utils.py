from datetime import datetime, timezone
from secrets import randbits

from dateutil.relativedelta import relativedelta
from uuid6 import UUID


def parse_params_to_uuid7(value: str | list[str]) -> UUID | list[UUID]:
    """
    Converts query parameters to UUIDv7 values.
    """
    if isinstance(value, str):
        if "," in value:
            value = value.split(",")
        else:
            value = UUID(value)

    if isinstance(value, list) and isinstance(value[0], str):
        value = [UUID(uuid) for uuid in value]

    return value


def datetime_to_uuid7(datetime: datetime) -> UUID:
    """
    The body of this function is taken from the `uuid6` package.
    https://github.com/oittaa/uuid6-python/blob/main/src/uuid6/__init__.py#L140-L147

    That package only generates UUIDv7s using the current timestamp, but we want to
    generate UUIDv7s using a timestamp from a different time.

    But there is an open issue for this:
    https://github.com/oittaa/uuid6-python/issues/150
    """

    timestamp_ms = int(datetime.timestamp()) * 1000
    uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
    uuid_int |= randbits(76)

    return UUID(int=uuid_int, version=7)


def datetime_from_uuid7(uuid7: UUID) -> datetime:
    """
    For any given UUIDv7, extract the timestamp from the UUIDv7 and return it as a datetime.

    If any other UUID is provided, an exception will be raised.
    """
    if not isinstance(uuid7, UUID):
        raise ValueError("uuid7 must be a UUIDv7 object")

    timestamp_ms = uuid7.time
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)


def uuid7_start(uuid: UUID) -> UUID:
    """
    Returns a UUIDv7 that represents the start of the day for the given UUID.
    """
    dt = datetime_from_uuid7(uuid).replace(hour=0, minute=0, second=0, microsecond=0)

    timestamp_ms = int(dt.timestamp()) * 1000
    uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80

    return UUID(int=uuid_int, version=7)


def uuid7_end(uuid: UUID, offset_days: int | None = 0) -> UUID:
    """
    Returns a UUIDv7 that represents the end of the day for the given UUID.

    If the offset_days is provided, the end of the day will be offset by the specified number of days.
    """
    dt = datetime_from_uuid7(uuid).replace(hour=0, minute=0, second=0, microsecond=0)
    dt = dt + relativedelta(days=(offset_days + 1), microseconds=-1)

    timestamp_ms = int(dt.timestamp()) * 1000
    uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80

    return UUID(int=uuid_int, version=7)


def uuid7_range(uuids: list) -> list:
    """
    For the given list of UUIDs, return a tuple of UUIDv7 values that represent the start and end of the range of days.
    """
    if not uuids:
        return []

    if isinstance(uuids[0], str):
        uuids = [UUID(uuid, version=7) for uuid in uuids]

    start = min(uuids)
    end = max(uuids)

    return [uuid7_start(start), uuid7_end(end)]
