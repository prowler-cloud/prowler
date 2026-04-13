import environ
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views import View

from api.db_router import MainRouter
from api.models import SAMLToken, User
from api.v1.serializers import TokenSocialLoginSerializer

env = environ.Env()


@method_decorator(login_required, name="dispatch")
class CloudGovCompleteView(View):
    """
    Post-UAA-auth bridge view.

    cg-django-uaa handles /auth/login and /auth/callback, authenticates the
    user, and creates a Django session.  LOGIN_REDIRECT_URL then sends the
    browser here.  This view mints Prowler JWT tokens, persists them in a
    short-lived SAMLToken record, and redirects the browser to the Next.js UI
    callback endpoint so next-auth can complete the sign-in flow.
    """

    def get(self, request):
        auth_url = env.str("AUTH_URL")
        error_url = f"{auth_url}?sso_saml_failed=true"

        # Resolve the Prowler User from the Django session identity.
        # The uaa_client backend stores the user under request.user using the
        # standard Django auth model; Prowler's User model is separate but
        # shares the same email address.
        prowler_user = (
            User.objects.using(MainRouter.admin_db)
            .filter(email__iexact=request.user.email)
            .first()
        )

        if prowler_user is None:
            return HttpResponseRedirect(error_url)

        serializer = TokenSocialLoginSerializer(
            data={"email": prowler_user.email}
        )
        if not serializer.is_valid():
            return HttpResponseRedirect(error_url)

        token_data = serializer.validated_data
        saml_token = SAMLToken.objects.using(MainRouter.admin_db).create(
            token=token_data, user=prowler_user
        )

        callback_url = env.str("SAML_SSO_CALLBACK_URL")
        return HttpResponseRedirect(f"{callback_url}?id={saml_token.id}")
