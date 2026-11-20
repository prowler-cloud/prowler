from typing import Optional

from prowler.providers.supabase.lib.service.service import (
    SupabaseProjectScope,
    SupabaseService,
)


class Auth(SupabaseService):
    """Retrieve the Supabase Auth (GoTrue) configuration of every project."""

    def __init__(self, provider):
        super().__init__("Auth", provider)
        self.configs: dict[str, SupabaseAuthConfig] = {}
        self._threading_call(self._fetch_config, self._list_projects())

    def _fetch_config(self, scope: SupabaseProjectScope) -> None:
        """Keep only the non-secret settings the checks evaluate."""
        raw = self._get_optional(
            f"/v1/projects/{scope.project_ref}/config/auth", "Auth config"
        )
        if raw is None:
            return
        self.configs[scope.project_ref] = SupabaseAuthConfig(
            **scope.model_dump(),
            disable_signup=raw.get("disable_signup"),
            external_email_enabled=raw.get("external_email_enabled"),
            external_anonymous_users_enabled=raw.get(
                "external_anonymous_users_enabled"
            ),
            mailer_autoconfirm=raw.get("mailer_autoconfirm"),
            mailer_otp_exp=raw.get("mailer_otp_exp"),
            password_min_length=raw.get("password_min_length"),
            password_required_characters=raw.get("password_required_characters"),
            password_hibp_enabled=raw.get("password_hibp_enabled"),
            mfa_totp_enroll_enabled=raw.get("mfa_totp_enroll_enabled"),
            mfa_phone_enroll_enabled=raw.get("mfa_phone_enroll_enabled"),
            mfa_web_authn_enroll_enabled=raw.get("mfa_web_authn_enroll_enabled"),
            refresh_token_rotation_enabled=raw.get("refresh_token_rotation_enabled"),
            security_captcha_enabled=raw.get("security_captcha_enabled"),
        )


class SupabaseAuthConfig(SupabaseProjectScope):
    """Non-secret Supabase Auth settings of a project.

    Provider client secrets, SMTP passwords, hook secrets and SMS credentials
    returned by the Management API are deliberately not stored.
    """

    disable_signup: Optional[bool] = None
    external_email_enabled: Optional[bool] = None
    external_anonymous_users_enabled: Optional[bool] = None
    mailer_autoconfirm: Optional[bool] = None
    mailer_otp_exp: Optional[int] = None
    password_min_length: Optional[int] = None
    password_required_characters: Optional[str] = None
    password_hibp_enabled: Optional[bool] = None
    mfa_totp_enroll_enabled: Optional[bool] = None
    mfa_phone_enroll_enabled: Optional[bool] = None
    mfa_web_authn_enroll_enabled: Optional[bool] = None
    refresh_token_rotation_enabled: Optional[bool] = None
    security_captcha_enabled: Optional[bool] = None

    @property
    def mfa_enrollment_enabled(self) -> bool:
        """True when users can enroll at least one second factor."""
        return bool(
            self.mfa_totp_enroll_enabled
            or self.mfa_phone_enroll_enabled
            or self.mfa_web_authn_enroll_enabled
        )
