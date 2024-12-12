import uuid
from unittest.mock import call, patch

import pytest

from api.db_utils import POSTGRES_TENANT_VAR, SET_CONFIG_QUERY
from api.decorators import set_tenant


@pytest.mark.django_db
class TestSetTenantDecorator:
    @patch("api.decorators.connection.cursor")
    def test_set_tenant(self, mock_cursor):
        mock_cursor.return_value.__enter__.return_value = mock_cursor

        @set_tenant
        def random_func(arg):
            return arg

        tenant_id = str(uuid.uuid4())

        result = random_func("test_arg", tenant_id=tenant_id)

        assert (
            call(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])
            in mock_cursor.execute.mock_calls
        )
        assert result == "test_arg"

    def test_set_tenant_exception(self):
        @set_tenant
        def random_func(arg):
            return arg

        with pytest.raises(KeyError):
            random_func("test_arg")
