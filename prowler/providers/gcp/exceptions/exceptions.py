from prowler.exceptions.exceptions import ProwlerException


class GCPBaseException(ProwlerException):
    def __init__(self, message, remediation, file):
        self.message = message
        self.remediation = remediation
        self.file = file
        self.provider = "GCP"
