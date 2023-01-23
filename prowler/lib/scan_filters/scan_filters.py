from prowler.lib.logger import logger


def is_resource_filtered(resource: str, audit_resources: list):
    """
    Check if it is a tags-based

    Returns True if it is filtered and False if it does not match the input filters
    """
    try:
        if resource in str(audit_resources):
            return True
        return False
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error} ({resource})"
        )
