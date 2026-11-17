"""Execute project validation in a separately admitted, disposable OCI worker.

This module reports *only* project checks. A trusted coordinator must perform
official validation independently in another worker and combine the reports.
Never call this from a userspace worker or a general-purpose worker process.
"""
from __future__ import annotations

import hashlib
import inspect
import sys
import types
from pathlib import Path
from typing import Any

from .domain._common import files_for, scoped_path
from .domain.validation import _result, _settings
from .errors import InvalidInput, PrerequisiteMissing, WorkerError

MAX_PROJECT_MODULE = 1024 * 1024


def run_project_rules(args: dict[str, Any]) -> dict[str, Any]:
    """Run a project Validator subclass; caller must establish OCI confinement."""
    root, files = files_for(args)
    if not files:
        raise InvalidInput("at least one CoNLL-U file is required")
    module_name = args.get("validator_module_path")
    class_name = args.get("validator_class_name")
    if not isinstance(module_name, str) or not isinstance(class_name, str) or not class_name.isidentifier():
        raise InvalidInput("project validator module and class names are invalid")
    source_path = scoped_path(root, module_name)
    if source_path.suffix != ".py":
        raise InvalidInput("project validator module must be a Python file")
    if source_path.stat().st_size > MAX_PROJECT_MODULE:
        raise InvalidInput("project validator module exceeds its size limit")
    source = source_path.read_bytes()
    if len(source) > MAX_PROJECT_MODULE:
        raise InvalidInput("project validator module exceeds its size limit")
    source_sha256 = hashlib.sha256(source).hexdigest()
    settings, options = _settings(args)
    try:
        from udtools import Validator
    except ImportError as exc:
        raise PrerequisiteMissing("the official udtools validator is not installed") from exc
    module = types.ModuleType("_ud_agent_project_validator")
    module.__file__ = str(source_path)
    # Only a fresh project-code worker may call this function. This insertion
    # permits ordinary sibling imports within its isolated snapshot.
    sys.path.insert(0, str(root))
    try:
        exec(compile(source, str(source_path), "exec"), module.__dict__)
        cls = getattr(module, class_name, None)
        if not isinstance(cls, type) or not issubclass(cls, Validator):
            raise InvalidInput("project validator class must inherit the official Validator")
        signature = inspect.signature(cls)
        if not any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values()):
            unsupported = sorted(set(settings) - set(signature.parameters))
            if unsupported:
                raise InvalidInput("project validator does not support requested parameters: " + ", ".join(unsupported))
        state = cls(**settings).validate_files([str(file) for file in files])
        report = _result(state, [file.relative_to(root).as_posix() for file in files], options, sentence_only=False)
    except WorkerError:
        raise
    except Exception as exc:
        raise WorkerError("PROJECT_VALIDATOR_FAILED", "project validator could not complete") from exc
    finally:
        # A hostile module can alter sys.path; remove the entry only if present.
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    report["coverage"]["content"] = "project_checks_only"
    report["coverage"]["project_rules"] = "completed"
    report["provenance"] = {"validator_module_path": source_path.relative_to(root).as_posix(),
                            "validator_class_name": class_name, "source_sha256": source_sha256}
    report["limitations"].append("Project results are not official UD validation; the coordinator must run official validation independently.")
    return report
