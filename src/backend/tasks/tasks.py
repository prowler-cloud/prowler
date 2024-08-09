from celery import shared_task

from celery.utils.log import get_task_logger

# TODO: add celery metadata to CustomLogger
logger = get_task_logger(__name__)


@shared_task
def debug_task(x, y):
    try:
        logger.info("Hello world")
    except Exception as e:
        logger.error(e)

    return x + y
