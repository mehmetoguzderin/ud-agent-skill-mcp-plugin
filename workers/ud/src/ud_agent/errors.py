"""Errors with machine-readable, stable worker codes."""

class WorkerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

class InvalidInput(WorkerError):
    def __init__(self, message: str):
        super().__init__("INVALID_INPUT", message)

class PrerequisiteMissing(WorkerError):
    def __init__(self, message: str):
        super().__init__("PREREQUISITE_MISSING", message)
