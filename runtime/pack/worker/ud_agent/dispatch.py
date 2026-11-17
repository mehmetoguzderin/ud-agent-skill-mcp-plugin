"""Dispatch the fixed public domain catalog; input never chooses a Python module."""
from __future__ import annotations
from importlib import import_module
from typing import Any

from .conllu.core import StaleInputError
from .errors import InvalidInput, WorkerError
from .generated_catalog import HANDLERS

_NAMES = {name: handler[0] for name, handler in HANDLERS.items()}
_MODULE_OPERATIONS = {module: " ".join(name for name, owner in _NAMES.items() if owner == module)
                      for module in dict.fromkeys(_NAMES.values())}


def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(name, str) or name not in _NAMES:
        raise InvalidInput("unknown domain operation")
    if not isinstance(args, dict):
        raise InvalidInput("arguments must be an object")
    module_name = _NAMES[name]
    try:
        module = import_module(f".domain.{module_name}", package="ud_agent")
    except ModuleNotFoundError as exc:
        if exc.name != f"ud_agent.domain.{module_name}":
            raise WorkerError("HANDLER_LOAD_FAILED", str(exc)) from exc
        raise WorkerError("HANDLER_UNAVAILABLE", f"operation is not available: {name}") from exc
    operation = getattr(module, name, None)
    if not callable(operation):
        raise WorkerError("HANDLER_UNAVAILABLE", f"operation is not available: {name}")
    try:
        result = operation(args)
    except StaleInputError as exc:
        raise WorkerError("CONFLICT", str(exc)) from exc
    except ValueError as exc:
        # Shared editing primitives use ValueError for invalid references and
        # other explicitly checked caller inputs.
        raise InvalidInput(str(exc)) from exc
    except KeyError as exc:
        raise InvalidInput(f"missing required input: {exc.args[0]}") from exc
    if not isinstance(result, dict):
        raise WorkerError("HANDLER_INVALID_RESULT", "operation did not return an object")
    return result
