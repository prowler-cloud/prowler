from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def delete_instance(model, pk: str):
    """
    Deletes an instance of the specified model.

    This function retrieves an instance of the provided model using its primary key
    and deletes it from the database.

    Args:
        model (Model): The Django model class from which to delete an instance.
        pk (str): The primary key of the instance to delete.

    Returns:
        tuple: A tuple containing the number of objects deleted and a dictionary
               with the count of deleted objects per model,
               including related models if applicable.

    Raises:
        model.DoesNotExist: If no instance with the provided primary key exists.
    """
    return model.objects.get(pk=pk).delete()
