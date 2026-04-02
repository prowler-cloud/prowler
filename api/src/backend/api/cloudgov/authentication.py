from django.conf import settings
from django.db import transaction
from uaa_client.authentication import UaaBackend

from api.account_bootstrap import provision_default_tenant_access
from api.db_router import MainRouter
from api.models import User


def _get_default_name_from_email(email: str) -> str:
    local_part = email.split("@", 1)[0].strip() or "user"
    if len(local_part) >= 3:
        return local_part[:150]
    return f"{local_part} user"[:150]


class ProwlerUaaBackend(UaaBackend):
    @staticmethod
    def get_role_name_for_email(email: str) -> str:
        normalized_email = email.strip().lower()
        email_role_map = getattr(settings, "UAA_EMAIL_ROLE_MAP", {}) or {}

        for configured_role, configured_emails in email_role_map.items():
            normalized_role = str(configured_role).strip().lower()

            if isinstance(configured_emails, str):
                if normalized_email == configured_role.strip().lower():
                    return configured_emails.strip().lower()
                continue

            if not isinstance(configured_emails, list):
                continue

            normalized_emails = {
                entry.strip().lower()
                for entry in configured_emails
                if isinstance(entry, str) and entry.strip()
            }
            if normalized_email in normalized_emails:
                return normalized_role

        return "admin"

    @classmethod
    def create_user_with_email(cls, email):
        normalized_email = email.strip().lower()
        role_name = cls.get_role_name_for_email(normalized_email)
        with transaction.atomic(using=MainRouter.admin_db):
            user = User.objects.db_manager(MainRouter.admin_db).create_user(
                email=normalized_email,
                name=_get_default_name_from_email(normalized_email),
            )
            if role_name == "admin":
                provision_default_tenant_access(user)
            else:
                provision_default_tenant_access(user, role_name=role_name)
        return user

    @classmethod
    def get_user_by_email(cls, email):
        normalized_email = email.strip().lower()
        try:
            return User.objects.using(MainRouter.admin_db).get(
                email__iexact=normalized_email
            )
        except User.DoesNotExist:
            if cls.should_create_user_for_email(normalized_email):
                return cls.create_user_with_email(normalized_email)
            return None