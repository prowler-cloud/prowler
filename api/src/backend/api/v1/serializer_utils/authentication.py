from api.db_router import MainRouter
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)


def blacklist_user_refresh_tokens(user_id):
    outstanding_token_ids = list(
        OutstandingToken.objects.using(MainRouter.admin_db)
        .filter(user_id=user_id)
        .values_list("id", flat=True)
    )
    if outstanding_token_ids:
        BlacklistedToken.objects.using(MainRouter.admin_db).bulk_create(
            [BlacklistedToken(token_id=token_id) for token_id in outstanding_token_ids],
            ignore_conflicts=True,
        )
