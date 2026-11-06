from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Trail


def data_event_resource_types(event_selector: dict) -> tuple[set[str], set[str]]:
    """Split the resource types of one advanced event selector by coverage.

    eventCategory and resources.type are the only two fields that widen what a selector
    logs; every other supported field (eventName, readOnly, resources.ARN, eventSource,
    eventType, userIdentity.arn, sessionCredentialFromConsole) removes events from the
    selection, and how many it removes cannot be read back from the trail configuration.

    Args:
        event_selector: The raw ``AdvancedEventSelectors`` entry from
            ``GetEventSelectors``.

    Returns:
        ``(complete, narrowed)``: the ``resources.type`` values this selector logs
        every data event for, and those it logs only a filtered subset of. Both are
        empty when the selector is not a data event selector.
    """
    event_categories = set()
    resource_types = set()
    has_narrowing_field = False

    for field_selector in event_selector.get("FieldSelectors") or []:
        field = field_selector.get("Field")
        # eventCategory and resources.type can only use the Equals operator.
        values = field_selector.get("Equals") or []
        if field == "eventCategory":
            event_categories.update(values)
        elif field == "resources.type":
            resource_types.update(values)
        else:
            # Includes a field selector with no Field at all: an unrecognizable filter is a
            # filter whose effect on coverage is unknown, not one with no effect.
            has_narrowing_field = True

    if event_categories != {"Data"}:
        return set(), set()
    if has_narrowing_field:
        return set(), resource_types
    return resource_types, set()


def trail_data_event_coverage(trail: Trail) -> tuple[set[str], set[str]]:
    """Report which data event resource types a trail's event selectors cover.

    Args:
        trail: The trail whose event selectors have already been retrieved.

    Basic (classic) event selectors need no special case: they carry ``DataResources``
    rather than ``FieldSelectors``, and their only supported resource types are
    AWS::DynamoDB::Table, AWS::Lambda::Function and AWS::S3::Object. Every other resource
    type requires an advanced event selector.

    Returns:
        ``(complete, narrowed)`` ``resources.type`` values. A type appearing in
        ``complete`` is never also reported as ``narrowed``.
    """
    complete = set()
    narrowed = set()
    for data_event in trail.data_events:
        selector_complete, selector_narrowed = data_event_resource_types(
            data_event.event_selector
        )
        complete |= selector_complete
        narrowed |= selector_narrowed
    return complete, narrowed - complete
