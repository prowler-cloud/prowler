from prowler.lib.resource.resource import Resource


class ResourceTest:
    def test_resource(self):
        resource = Resource(service="test_service")
        assert resource.service == "test_service"
        assert isinstance(resource, Resource)
