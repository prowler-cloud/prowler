from django.db import models

from api.rls import RowLevelSecurityProtectedModel, RowLevelSecurityConstraint


class Test(RowLevelSecurityProtectedModel):
    name = models.CharField(max_length=100)

    class Meta:
        db_table = "test"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            )
        ]
