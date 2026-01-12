from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.openapi import AutoSchema


class CombinedJWTOrAPIKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "api.authentication.CombinedJWTOrAPIKeyAuthentication"
    name = "JWT or API Key"

    def get_security_definition(self, auto_schema: AutoSchema):  # noqa: F841
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Supports both JWT Bearer tokens and API Key authentication. "
            "Use `Bearer <token>` for JWT or `Api-Key <key>` for API keys.",
        }
