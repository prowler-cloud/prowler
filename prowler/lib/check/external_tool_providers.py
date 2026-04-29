# Providers that delegate scanning to an external tool (e.g. Trivy, promptfoo)
# and bypass standard check/service loading.
#
# Kept in a leaf module with no imports so it can be referenced from both
# prowler.config.config and prowler.lib.check.utils without forming an
# import cycle.
EXTERNAL_TOOL_PROVIDERS = frozenset({"iac", "llm", "image"})
