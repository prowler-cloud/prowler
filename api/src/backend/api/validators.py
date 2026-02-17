import re
import string

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class MaximumLengthValidator:
    def __init__(self, max_length=72):
        self.max_length = max_length

    def validate(self, password, user=None):
        if len(password) > self.max_length:
            raise ValidationError(
                _(
                    "This password is too long. It must contain no more than %(max_length)d characters."
                ),
                code="password_too_long",
                params={"max_length": self.max_length},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain no more than {self.max_length} characters."
        )


class SpecialCharactersValidator:
    def __init__(self, special_characters=None, min_special_characters=1):
        # Use string.punctuation if no custom characters provided
        self.special_characters = special_characters or string.punctuation
        self.min_special_characters = min_special_characters

    def validate(self, password, user=None):
        if (
            sum(1 for char in password if char in self.special_characters)
            < self.min_special_characters
        ):
            raise ValidationError(
                _("This password must contain at least one special character."),
                code="password_no_special_characters",
                params={
                    "special_characters": self.special_characters,
                    "min_special_characters": self.min_special_characters,
                },
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least one special character from: {self.special_characters}"
        )


class UppercaseValidator:
    def __init__(self, min_uppercase=1):
        self.min_uppercase = min_uppercase

    def validate(self, password, user=None):
        if sum(1 for char in password if char.isupper()) < self.min_uppercase:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_uppercase)d uppercase letter."
                ),
                code="password_no_uppercase_letters",
                params={"min_uppercase": self.min_uppercase},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_uppercase} uppercase letter."
        )


class LowercaseValidator:
    def __init__(self, min_lowercase=1):
        self.min_lowercase = min_lowercase

    def validate(self, password, user=None):
        if sum(1 for char in password if char.islower()) < self.min_lowercase:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_lowercase)d lowercase letter."
                ),
                code="password_no_lowercase_letters",
                params={"min_lowercase": self.min_lowercase},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_lowercase} lowercase letter."
        )


class NumericValidator:
    def __init__(self, min_numeric=1):
        self.min_numeric = min_numeric

    def validate(self, password, user=None):
        if sum(1 for char in password if char.isdigit()) < self.min_numeric:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_numeric)d numeric character."
                ),
                code="password_no_numeric_characters",
                params={"min_numeric": self.min_numeric},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_numeric} numeric character."
        )


def _parse_cron_base(value: str, min_value: int, max_value: int) -> None:
    if value == "*":
        return

    if "-" in value:
        range_parts = value.split("-", 1)
        if len(range_parts) != 2 or not range_parts[0] or not range_parts[1]:
            raise ValidationError("Invalid cron expression.")
        if not range_parts[0].isdigit() or not range_parts[1].isdigit():
            raise ValidationError("Invalid cron expression.")

        start = int(range_parts[0])
        end = int(range_parts[1])
        if start > end or start < min_value or end > max_value:
            raise ValidationError("Invalid cron expression.")
        return

    if not value.isdigit():
        raise ValidationError("Invalid cron expression.")

    number = int(value)
    if number < min_value or number > max_value:
        raise ValidationError("Invalid cron expression.")


def _validate_cron_field(value: str, min_value: int, max_value: int) -> None:
    if not value:
        raise ValidationError("Invalid cron expression.")

    if not re.fullmatch(r"[\d*/,\-]+", value):
        raise ValidationError("Invalid cron expression.")

    items = value.split(",")
    if any(not item for item in items):
        raise ValidationError("Invalid cron expression.")

    for item in items:
        if "/" in item:
            step_parts = item.split("/", 1)
            if len(step_parts) != 2 or not step_parts[0] or not step_parts[1]:
                raise ValidationError("Invalid cron expression.")

            base, step = step_parts
            if not step.isdigit() or int(step) <= 0:
                raise ValidationError("Invalid cron expression.")

            _parse_cron_base(base, min_value, max_value)
            continue

        _parse_cron_base(item, min_value, max_value)


def cron_5_fields_validator(value: str) -> None:
    if not isinstance(value, str):
        raise ValidationError("Invalid cron expression.")

    parts = value.strip().split()
    if len(parts) != 5:
        raise ValidationError("Cron expression must contain exactly 5 fields in UTC.")

    # minute hour day-of-month month day-of-week (Celery: 0-6)
    field_ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
    for part, (min_value, max_value) in zip(parts, field_ranges, strict=False):
        _validate_cron_field(part, min_value, max_value)
