"""Tests for ``MinimalSerializerMixin``, the exclusion rule nearly every model uses.

Almost every response model mixes this in so a list response does not spend
tokens repeating ``null``/``""``/``[]`` for a field that has nothing to say.
The rule is intentionally narrow -- it is a token-budget optimization, not a
generic "falsy" filter -- so ``0`` and ``False`` must survive it, and a
subclass must be able to override ``_should_exclude`` to keep a field the
mixin would otherwise drop.
"""

from pydantic import BaseModel

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin


class _SampleModel(MinimalSerializerMixin, BaseModel):
    name: str
    nickname: str | None = None
    tags: list[str] = []
    metadata: dict = {}
    count: int = 0
    enabled: bool = False


def test_none_values_are_dropped():
    model = _SampleModel(name="a", nickname=None)

    assert "nickname" not in model.model_dump()


def test_empty_string_is_dropped():
    model = _SampleModel(name="")

    assert "name" not in model.model_dump()


def test_empty_list_is_dropped():
    model = _SampleModel(name="a", tags=[])

    assert "tags" not in model.model_dump()


def test_empty_dict_is_dropped():
    model = _SampleModel(name="a", metadata={})

    assert "metadata" not in model.model_dump()


def test_populated_list_and_dict_survive():
    model = _SampleModel(name="a", tags=["x"], metadata={"k": "v"})

    dumped = model.model_dump()
    assert dumped["tags"] == ["x"]
    assert dumped["metadata"] == {"k": "v"}


def test_zero_is_not_treated_as_empty():
    """A count of zero is a fact ('nothing found'), not nothing to say."""
    model = _SampleModel(name="a", count=0)

    assert model.model_dump()["count"] == 0


def test_false_is_not_treated_as_empty():
    """A disabled flag is a fact, not nothing to say."""
    model = _SampleModel(name="a", enabled=False)

    assert model.model_dump()["enabled"] is False


def test_a_subclass_can_override_should_exclude_to_keep_a_field():
    """Some models (e.g. ``SimplifiedProvider``) always report a field even when
    ``None``, because its absence would be mistaken for "not yet known" rather
    than "checked, and it is empty"."""

    class _AlwaysKeepsNickname(_SampleModel):
        def _should_exclude(self, key: str, value) -> bool:
            if key == "nickname":
                return False
            return super()._should_exclude(key, value)

    model = _AlwaysKeepsNickname(name="a", nickname=None)

    dumped = model.model_dump()
    assert "nickname" in dumped
    assert dumped["nickname"] is None
    # The override only widens the exception for `nickname`; other fields keep
    # the inherited exclusion behaviour.
    assert "metadata" not in dumped
