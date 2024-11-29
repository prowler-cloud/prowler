from unittest.mock import patch, call

import pytest

from api.decorators import set_tenant


@pytest.mark.django_db
class TestSetTenantDecorator:
    @patch("api.decorators.connection.cursor")
    def test_set_tenant(self, mock_cursor):
        mock_cursor.return_value.__enter__.return_value = mock_cursor

        @set_tenant
        def random_func(arg):
            return arg

        tenant_id = "1234-abcd-5678"

        result = random_func("test_arg", tenant_id=tenant_id)

        assert (
            call(f"SELECT set_config('api.tenant_id', '{tenant_id}', TRUE);")
            in mock_cursor.execute.mock_calls
        )
        assert result == "test_arg"

    def test_set_tenant_exception(self):
        @set_tenant
        def random_func(arg):
            return arg

        with pytest.raises(KeyError):
            random_func("test_arg")
