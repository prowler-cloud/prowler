"""Tests for the provider-label scoping added to RELATIONSHIP_SYNC_TEMPLATE."""

from tasks.jobs.attack_paths.config import get_provider_label
from tasks.jobs.attack_paths.queries import (
    RELATIONSHIP_SYNC_TEMPLATE,
    render_cypher_template,
)


class TestRelationshipSyncTemplate:
    def test_template_contains_provider_label_placeholder(self):
        assert "__PROVIDER_LABEL__" in RELATIONSHIP_SYNC_TEMPLATE

    def test_template_renders_with_rel_type_and_provider_label(self):
        provider_id = "00000000-0000-0000-0000-000000000abc"
        label = get_provider_label(provider_id)

        rendered = render_cypher_template(
            RELATIONSHIP_SYNC_TEMPLATE,
            {"__REL_TYPE__": "RESOURCE", "__PROVIDER_LABEL__": label},
        )

        assert f":`{label}`" in rendered
        assert ":RESOURCE" in rendered
        assert "__PROVIDER_LABEL__" not in rendered
        assert "__REL_TYPE__" not in rendered
