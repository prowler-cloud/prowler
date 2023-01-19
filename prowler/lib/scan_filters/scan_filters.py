from prowler.lib.logger import logger


def is_resource_filtered(resource_tags: list, audit_tags: list):
    """
    Check if it is a tags-based

    Returns True if it is filtered or there is no input filters and False if it does not match the input filters
    """
    try:
        if all(x in resource_tags for x in audit_tags):
            return True
        return False
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
