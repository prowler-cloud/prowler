import pytest
from django.core.exceptions import ObjectDoesNotExist

from api.models import Provider
from tasks.jobs.deletion import delete_instance


@pytest.mark.django_db
class TestDeleteInstance:
    def test_delete_instance_success(self, providers_fixture):
        instance = providers_fixture[0]
        result = delete_instance(Provider, instance.id)

        assert result
        with pytest.raises(ObjectDoesNotExist):
            Provider.objects.get(pk=instance.id)

    def test_delete_instance_does_not_exist(self):
        non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

        with pytest.raises(ObjectDoesNotExist):
            delete_instance(Provider, non_existent_pk)
