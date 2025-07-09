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

    def validate(self, password, user=None):
        if not any(char in self.special_characters for char in password):
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
