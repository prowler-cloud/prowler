"""
This module contains functions with user privileges in Azure.
"""


def is_privileged_user(user, privileged_roles) -> bool:
    """
    Checks if a user is a privileged user.

    Args:
        user: An object representing the user to be checked.
        privileged_roles: A dictionary containing privileged roles.

    Returns:
        A boolean value indicating whether the user is a privileged user.
    """

    is_privileged = False

    for role in privileged_roles.values():
        if user in role.members:
            is_privileged = True
            break

    return is_privileged
