import logging

import pytest

from api.rls import Tenant


@pytest.fixture(autouse=True)
def disable_logging():
    logging.disable(logging.CRITICAL)


@pytest.fixture
def get_tenant():
    tenant = Tenant.objects.create(
        name="Tenant One",
        inserted_at="2023-01-01T00:00:00Z",
        updated_at="2023-01-02T00:00:00Z",
    )
    return tenant


@pytest.fixture
def tenant_header(get_tenant):
    return {"X-Tenant-ID": str(get_tenant.id)}
