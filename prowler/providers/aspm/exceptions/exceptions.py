"""ASPM Provider exceptions."""


class ASPMBaseException(Exception):
    """Base exception for the ASPM provider."""

    def __init__(self, message: str = ""):
        self.message = message
        super().__init__(self.message)


class ASPMManifestNotFoundError(ASPMBaseException):
    """Raised when the ASPM agent manifest file is not found."""

    def __init__(self, path: str):
        super().__init__(f"ASPM manifest file not found: {path}")


class ASPMManifestInvalidError(ASPMBaseException):
    """Raised when the ASPM agent manifest file cannot be parsed."""

    def __init__(self, path: str, detail: str = ""):
        msg = f"ASPM manifest file is invalid: {path}"
        if detail:
            msg += f" — {detail}"
        super().__init__(msg)


class ASPMNoAgentsFoundError(ASPMBaseException):
    """Raised when the manifest contains no agents to assess."""

    def __init__(self):
        super().__init__(
            "No agents found in the ASPM manifest. "
            "Ensure the manifest contains at least one entry under 'agents'."
        )
