class AzureException(Exception):
    """
    Exception raised when dealing with Azure Provider/Azure audit info instance

    Attributes:
        message -- message to be displayed
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
