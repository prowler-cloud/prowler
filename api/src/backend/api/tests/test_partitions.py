import pytest
from dateutil.relativedelta import relativedelta

from api.partitions import relative_months_or_none


class TestRelativeMonthsOrNone:
    def test_none_keeps_partitions_indefinitely(self):
        assert relative_months_or_none(None) is None

    @pytest.mark.parametrize("value", [0, -1])
    def test_non_positive_keeps_partitions_indefinitely(self, value):
        assert relative_months_or_none(value) is None

    @pytest.mark.parametrize("months", [1, 3, 12])
    def test_value_is_interpreted_as_months(self, months):
        assert relative_months_or_none(months) == relativedelta(months=months)

    def test_value_is_not_interpreted_as_days(self):
        assert relative_months_or_none(12) != relativedelta(days=12)
