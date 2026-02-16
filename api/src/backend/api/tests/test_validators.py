import pytest
from django.core.exceptions import ValidationError

from api.validators import cron_5_fields_validator


class TestCron5FieldsValidator:
    @pytest.mark.parametrize(
        "expression",
        [
            "* * * * *",
            "*/30 * * * *",
            "0 2 * * 1-5",
            "15,45 8-18 * 1,6,12 1-5",
        ],
    )
    def test_accepts_valid_expressions(self, expression):
        cron_5_fields_validator(expression)

    @pytest.mark.parametrize(
        "expression",
        [
            "*/30 * * *",
            "@daily",
            "0 24 * * *",
            "0 2 0 * *",
            "0 2 * 13 *",
            "0 2 * * 9",
            "*/0 * * * *",
            "",
        ],
    )
    def test_rejects_invalid_expressions(self, expression):
        with pytest.raises(ValidationError):
            cron_5_fields_validator(expression)
