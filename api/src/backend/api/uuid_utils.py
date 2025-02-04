from datetime import datetime, timezone
from random import getrandbits

from dateutil.relativedelta import relativedelta
from rest_framework_json_api.serializers import ValidationError
from uuid6 import UUID


def transform_into_uuid7(uuid_obj: UUID) -> UUID:
    """
    Validates that the given UUID object is a UUIDv7 and returns it.

    This function checks if the provided UUID object is of version 7.
    If it is, it returns a new UUID object constructed from the uppercase
    hexadecimal representation of the input UUID. If not, it raises a ValidationError.

    Args:
        uuid_obj (UUID): The UUID object to validate and transform.

    Returns:
        UUID: A new UUIDv7 object constructed from the uppercase hexadecimal
        representation of the input UUID.

    Raises:
        ValidationError: If the provided UUID is not a version 7 UUID.
    """
    try:
        if uuid_obj.version != 7:
            raise ValueError
        return UUID(hex=uuid_obj.hex.upper())
    except ValueError:
        raise ValidationError("Invalid UUIDv7 value.")


def datetime_to_uuid7(dt: datetime) -> UUID:
    """
    Generates a UUIDv7 from a given datetime object.

    Constructs a UUIDv7 using the provided datetime timestamp.
    Ensures that the version and variant bits are set correctly.

    Args:
        dt: A datetime object representing the desired timestamp for the UUIDv7.

    Returns:
        A UUIDv7 object corresponding to the given datetime.
    """
    timestamp_ms = int(dt.timestamp() * 1000) & 0xFFFFFFFFFFFF  # 48 bits

    # Generate 12 bits of randomness for the sequence
    rand_seq = getrandbits(12)
    # Generate 62 bits of randomness for the node
    rand_node = getrandbits(62)

    # Build the UUID integer
    uuid_int = timestamp_ms << 80  # Shift timestamp to bits 80-127

    # Set the version to 7 in bits 76-79
    uuid_int |= 0x7 << 76

    # Set 12 bits of randomness in bits 64-75
    uuid_int |= rand_seq << 64

    # Set the variant to "10" in bits 62-63
    uuid_int |= 0x2 << 62

    # Set 62 bits of randomness in bits 0-61
    uuid_int |= rand_node

    return UUID(int=uuid_int)


def datetime_from_uuid7(uuid7: UUID) -> datetime:
    """
    Extracts the timestamp from a UUIDv7 and returns it as a datetime object.

    Args:
        uuid7: A UUIDv7 object.

    Returns:
        A datetime object representing the timestamp encoded in the UUIDv7.
    """
    timestamp_ms = uuid7.time
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)


def uuid7_start(uuid_obj: UUID) -> UUID:
    """
    Returns a UUIDv7 that represents the start of the day for the given UUID.

    Args:
        uuid_obj: A UUIDv7 object.

    Returns:
        A UUIDv7 object representing the start of the day for the given UUID's timestamp.
    """
    start_of_day = datetime_from_uuid7(uuid_obj).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return datetime_to_uuid7(start_of_day)


def uuid7_end(uuid_obj: UUID, offset_months: int = 1) -> UUID:
    """
    Returns a UUIDv7 that represents the end of the month for the given UUID.

    Args:
        uuid_obj: A UUIDv7 object.
        offset_days: Number of months to offset from the given UUID's date. Defaults to 1 to handle if
        partitions are not being used, if so the value will be the one set at FINDINGS_TABLE_PARTITION_MONTHS.

    Returns:
        A UUIDv7 object representing the end of the month for the given UUID's date plus offset_months.
    """
    end_of_month = datetime_from_uuid7(uuid_obj).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    end_of_month += relativedelta(months=offset_months, microseconds=-1)
    return datetime_to_uuid7(end_of_month)


def uuid7_range(uuid_list: list[UUID]) -> list[UUID]:
    """
    For the given list of UUIDv7s, returns the start and end UUIDv7 values that represent
    the range of days covered by the UUIDs.

    Args:
        uuid_list: A list of UUIDv7 objects.

    Returns:
        A list containing two UUIDv7 objects: the start and end of the day range.

    Raises:
        ValidationError: If the list is empty or contains invalid UUIDv7 objects.
    """
    if not uuid_list:
        raise ValidationError("UUID list is empty.")

    try:
        start_uuid = min(uuid_list, key=lambda u: u.time)
        end_uuid = max(uuid_list, key=lambda u: u.time)
    except AttributeError:
        raise ValidationError("Invalid UUIDv7 objects in the list.")

    start_range = uuid7_start(start_uuid)
    end_range = uuid7_end(end_uuid)

    return [start_range, end_range]
