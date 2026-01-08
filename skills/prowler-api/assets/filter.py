# Example: FilterSet with Custom Validation
# Source: api/src/backend/api/filters.py

from datetime import date

from django_filters import ChoiceFilter, DateFilter, FilterSet
from rest_framework.exceptions import ValidationError

from api.models import DailySeveritySummary, Provider


class DailySeveritySummaryFilter(FilterSet):
    """
    FilterSet with required field validation and date range limits.

    Key patterns:
    1. Override filter_queryset() for custom validation
    2. Use filter_noop for fields that need validation but no filtering
    3. Expose computed values to view via request attributes
    """

    MAX_DATE_RANGE_DAYS = 365

    provider_id = UUIDFilter(field_name="provider_id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider_id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider",
        choices=Provider.ProviderChoices.choices,
    )
    provider_type__in = ChoiceInFilter(
        field_name="provider__provider",
        choices=Provider.ProviderChoices.choices,
    )
    date_from = DateFilter(method="filter_noop")
    date_to = DateFilter(method="filter_noop")

    class Meta:
        model = DailySeveritySummary
        fields = ["provider_id"]

    def filter_noop(self, queryset, name, value):
        """No-op filter - validation happens in filter_queryset."""
        return queryset

    def filter_queryset(self, queryset):
        """Custom validation for required fields and date range."""
        # Required field validation
        if not self.data.get("date_from"):
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": "400",
                        "source": {"pointer": "filter[date_from]"},
                        "code": "required",
                    }
                ]
            )

        today = date.today()
        date_from = self.form.cleaned_data.get("date_from")
        date_to = min(self.form.cleaned_data.get("date_to") or today, today)

        # Date range validation
        if (date_to - date_from).days > self.MAX_DATE_RANGE_DAYS:
            raise ValidationError(
                [
                    {
                        "detail": f"Date range cannot exceed {self.MAX_DATE_RANGE_DAYS} days.",
                        "status": "400",
                        "source": {"pointer": "filter[date_from]"},
                        "code": "invalid",
                    }
                ]
            )

        # Expose dates to view for use in aggregation
        self.request._date_from = date_from
        self.request._date_to = date_to

        queryset = queryset.filter(date__lte=date_to)
        return super().filter_queryset(queryset)


class TaskFilter(FilterSet):
    """
    FilterSet with custom filter methods for state mapping.

    Key pattern: Use method= parameter for complex filtering logic.
    """

    name = CharFilter(field_name="task_runner_task__task_name", lookup_expr="exact")
    name__icontains = CharFilter(
        field_name="task_runner_task__task_name",
        lookup_expr="icontains",
    )
    state = ChoiceFilter(
        choices=StateChoices.choices,
        method="filter_state",
        lookup_expr="exact",
    )

    # Inverse mapping for state translation
    task_state_inverse_mapping_values = {
        v: k for k, v in TaskBase.state_mapping.items()
    }

    def filter_state(self, queryset, name, value):
        """Custom filter with state mapping and validation."""
        if value not in StateChoices:
            raise ValidationError(
                f"Invalid state value: '{value}'. Valid values: {', '.join(StateChoices)}"
            )
        return queryset.filter(
            task_runner_task__status=self.task_state_inverse_mapping_values[value]
        )

    class Meta:
        model = Task
        fields = []
