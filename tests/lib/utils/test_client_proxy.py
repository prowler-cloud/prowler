import pytest

from prowler.lib.utils.proxy import ClientProxy


class ClassForTest:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def get_a(self):
        return self.a

    def get_b(self):
        return self.b


class TestClientProxy:

    def test_proxy_ok(self):
        obj = ClientProxy(ClassForTest, a=1, b=2)
        assert obj.get_a() == 1
        assert obj.get_b() == 2

    def test_proxy_wrong_args(self):
        obj = ClientProxy(ClassForTest, a=1)

        # should raise an error
        with pytest.raises(TypeError):
            obj.get_a()

    def test_proxy_wrong_args2(self):
        obj = ClientProxy(ClassForTest, a=1, b=2, c=3)

        # should raise an error
        with pytest.raises(TypeError):
            obj.get_a()

    def test_check_object_is_not_instance(self):
        obj = ClientProxy(ClassForTest, a=1, b=2)

        assert obj._instance is None

        obj.get_a()

        assert obj._instance is not None
