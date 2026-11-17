"""Official UD validator integration; never substitutes partial local checks for a pass."""
from __future__ import annotations
import inspect
import io
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from pathlib import Path
from typing import Any

from ..errors import InvalidInput, PrerequisiteMissing, WorkerError
from ._common import files_for, root_path, scoped_path


def _settings(args: dict[str, Any], language_override: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise InvalidInput("options must be an object")
    allowed = {"language_code", "level", "coref", "test_filters", "exclude_filters", "check_families", "repository_name"}
    unknown = set(options) - allowed
    if unknown:
        raise InvalidInput("unsupported validation options: " + ", ".join(sorted(unknown)))
    families = options.get("check_families", ["content"])
    if (not isinstance(families, list) or not families
            or any(not isinstance(family, str) or family not in {"content", "repository", "documentation"} for family in families)
            or len(families) != len(set(families))):
        raise InvalidInput("check_families must be a nonempty unique selection of content, repository and documentation")
    language = language_override or options.get("language_code")
    if not isinstance(language, str) or not language.strip():
        raise InvalidInput("an explicit language_code is required")
    level = options.get("level", 5)
    if isinstance(level, bool) or not isinstance(level, int) or not 1 <= level <= 5:
        raise InvalidInput("validation level must be an integer from 1 to 5")
    context = args.get("ud_context_path")
    if not isinstance(context, str) or not context:
        raise InvalidInput("ud_context_path is required")
    path = Path(context)
    if not path.is_absolute() or not path.exists():
        raise InvalidInput("ud_context_path must be an existing absolute path")
    if path.is_file():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            rule_dir = manifest["rule_dir"]
            path = (path.parent / rule_dir).resolve(strict=True) if not Path(rule_dir).is_absolute() else Path(rule_dir).resolve(strict=True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise InvalidInput("invalid context manifest or rule_dir") from exc
    if not path.is_dir():
        raise InvalidInput("context rule directory does not exist")
    required = {"upos.json", "feats.json", "udeprels.json", "deprels.json", "edeprels.json", "data.json", "tospace.json"}
    missing = sorted(item for item in required if not (path / item).is_file())
    if missing:
        raise PrerequisiteMissing("UD context is missing rules: " + ", ".join(missing))
    kwargs: dict[str, Any] = {"lang": language.strip(), "level": level, "datapath": str(path), "output": None, "max_store": 0}
    if "coref" in options:
        if not isinstance(options["coref"], bool):
            raise InvalidInput("coref must be a boolean")
        kwargs["check_coref"] = options["coref"]
    filters = {}
    for option_name, upstream_name in (("test_filters", "include_only"), ("exclude_filters", "exclude")):
        if option_name in options:
            value = options[option_name]
            if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
                raise InvalidInput(f"{option_name} must be an array of nonempty strings")
            filters[upstream_name] = value
    if filters:
        kwargs["args"] = Namespace(**filters)
    return kwargs, options


def _validator(settings: dict[str, Any]):
    try:
        from udtools import Validator
    except ImportError as exc:
        raise PrerequisiteMissing("the official udtools validator is not installed") from exc
    try:
        sig = inspect.signature(Validator)
        if not any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            unsupported = sorted(set(settings) - set(sig.parameters))
            if unsupported:
                raise InvalidInput("validator does not support requested parameters: " + ", ".join(unsupported))
        return Validator(**settings)
    except WorkerError:
        raise
    except Exception as exc:
        raise WorkerError("VALIDATOR_INITIALIZATION_FAILED", str(exc)) from exc


def _result(state: Any, files: list[str], options: dict[str, Any], *, sentence_only: bool) -> dict[str, Any]:
    try:
        incidents = [json.loads(item.json()) for item in state.error_tracker]
        passed = bool(state.passed())
    except (AttributeError, TypeError, ValueError) as exc:
        raise WorkerError("VALIDATOR_INCOMPLETE", "could not obtain complete structured validator incidents") from exc
    return {"passed": passed, "incidents": incidents,
            "scope": {"file_paths": files, "sentence_only": sentence_only,
                      "filtered": bool(options.get("test_filters") or options.get("exclude_filters"))},
            "coverage": {"content": "completed", "repository": "not_requested", "documentation": "not_requested",
                         "project_rules": "not_requested", "release_policy": "not_requested"},
            "limitations": ["Local validation does not certify official online release acceptance."] +
                           (["Sentence-only validation cannot check unseen treebank-wide conditions."] if sentence_only else [])}


def validation_report(args: dict[str, Any]) -> dict[str, Any]:
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    settings, options = _settings(args)
    families = options.get("check_families", ["content"])
    if "content" in families:
        validator = _validator(settings)
        try:
            state = validator.validate_files([str(path) for path in paths])
        except Exception as exc:
            raise WorkerError("VALIDATOR_FAILED", str(exc)) from exc
        result = _result(state, [p.relative_to(root).as_posix() for p in paths], options, sentence_only=False)
    else:
        result = {"passed": True, "incidents": [], "scope": {"file_paths": [p.relative_to(root).as_posix() for p in paths], "sentence_only": False},
                  "coverage": {family: "not_requested" for family in ("content", "repository", "documentation", "project_rules", "release_policy")},
                  "limitations": ["Local validation does not certify official online release acceptance."]}
    additional = [family for family in families if family != "content"]
    if additional:
        from ..repository_checks import repository_checks
        repository = repository_checks(root, args["ud_context_path"], options, additional)
        result["passed"] = result["passed"] and repository["passed"]
        result["incidents"].extend(repository["incidents"])
        result["coverage"].update(repository["coverage"])
        result["provenance"] = repository["provenance"]
    return result


def sentence_validation_report(args: dict[str, Any]) -> dict[str, Any]:
    root_path(args)
    sentence = args.get("sentence_conllu")
    if not isinstance(sentence, str) or not sentence:
        raise InvalidInput("sentence_conllu must be a nonempty string")
    settings, options = _settings(args, args.get("language_code"))
    if options.get("check_families", ["content"]) != ["content"]:
        raise InvalidInput("sentence-only validation supports the content check family only")
    validator = _validator(settings)
    stream = io.StringIO(sentence)
    stream.name = "<sentence>"
    try:
        state = validator.validate_file_handle(stream)
    except Exception as exc:
        raise WorkerError("VALIDATOR_FAILED", str(exc)) from exc
    return _result(state, [], options, sentence_only=True)


def _project_pipe_child(command: list[str], request: bytes, env: dict[str, str], *,
                        limit: int = 32 * 1024 * 1024, timeout: float = 300) -> tuple[int, bytes]:
    """Bound a private result pipe without Windows-only inherited descriptors.

    The fixed child duplicates stdout before redirecting project output away.
    A request file avoids a blocked input writer; nonblocking pipe reads keep
    both the byte bound and deadline under the parent's control.
    """
    if not 0 < limit <= 32 * 1024 * 1024 or not 0 < timeout <= 300:
        raise ValueError("invalid project subprocess bounds")
    with tempfile.TemporaryFile() as input_file:
        input_file.write(request); input_file.seek(0)
        process = subprocess.Popen(command, stdin=input_file, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env, close_fds=True, bufsize=0)
        try:
            assert process.stdout is not None
            descriptor = process.stdout.fileno()
            # Python 3.12+ supports nonblocking pipes on Windows as well.
            os.set_blocking(descriptor, False)
            deadline, raw = time.monotonic() + timeout, bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    chunk = os.read(descriptor, min(65536, limit + 1 - len(raw)))
                except BlockingIOError:
                    if process.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > limit:
                    raise WorkerError("PROJECT_VALIDATOR_FAILED", "validation output exceeded its limit")
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            return code, bytes(raw)
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            finally:
                if process.stdout is not None:
                    process.stdout.close()


def _project_child(mode: str, args: dict[str, Any], upstream: str) -> dict[str, Any]:
    """Collect one bounded subprocess result without sharing Python state."""
    worker_root = str(Path(__file__).resolve().parents[2])
    entry = str(Path(worker_root) / "ud_agent" / "project_child.py")
    try:
        request = json.dumps(args, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidInput("project request is not valid JSON") from exc
    if len(request) > 16 * 1024 * 1024:
        raise InvalidInput("project request exceeds the size limit")
    # A private result channel isolates structured data from project output.
    # POSIX additionally applies RLIMIT_FSIZE before importing project code;
    # Windows uses a parent-bounded pipe, never an unbounded result file.
    # Neither route substitutes for the independently admitted outer OCI job.
    try:
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": tempfile.gettempdir()}
        command = [sys.executable, "-I", "-B", entry, worker_root, upstream]
        if sys.platform == "win32":
            env.update({name: os.environ[name] for name in ("SystemRoot", "WINDIR") if name in os.environ})
            env.update(PATH=str(Path(sys.executable).parent), TEMP=tempfile.gettempdir(), TMP=tempfile.gettempdir())
            code, raw = _project_pipe_child([*command, "stdout", mode], request, env)
        else:
            with tempfile.TemporaryFile() as output:
                result = subprocess.run([*command, str(output.fileno()), mode],
                                        input=request, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        pass_fds=(output.fileno(),), env=env, timeout=300, check=False)
                code = result.returncode
                output.seek(0)
                raw = output.read(32 * 1024 * 1024 + 1)
        if code != 0:
            raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation subprocess did not complete")
    except subprocess.TimeoutExpired as exc:
        raise WorkerError("PROJECT_VALIDATOR_TIMEOUT", f"{mode} validation timed out") from exc
    except OSError as exc:
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation subprocess could not start") from exc
    if len(raw) > 32 * 1024 * 1024:
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation output exceeded its limit")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation returned invalid output") from exc
    if not isinstance(value, dict):
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation returned invalid output")
    if value.get("ok") is not True:
        error = value.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str) and isinstance(error.get("message"), str):
            raise WorkerError(error["code"], error["message"])
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation did not complete")
    report = value.get("result")
    if not isinstance(report, dict) or not isinstance(report.get("passed"), bool):
        raise WorkerError("PROJECT_VALIDATOR_FAILED", f"{mode} validation returned invalid output")
    return report


def project_consistency_report(args: dict[str, Any]) -> dict[str, Any]:
    """Run official and project validators separately inside a fresh OCI worker.

    The coordinator must execute this operation only in an admitted, isolated
    OCI worker. The userspace bootstrap explicitly does not expose this route.
    Separate subprocesses here prevent Python-state sharing, but are not a
    substitute for independently admitted OCI jobs against hostile project code.
    """
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    module = args.get("validator_module_path")
    cls = args.get("validator_class_name")
    if not isinstance(module, str) or not isinstance(cls, str) or not cls.isidentifier():
        raise InvalidInput("project validator module and class names are invalid")
    source = scoped_path(root, module)
    if source.suffix != ".py" or source.stat().st_size > 1024 * 1024:
        raise InvalidInput("project validator must be a bounded Python file")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    settings, _ = _settings(args)
    del settings  # Validate the identical profile before invoking either child.
    try:
        import udtools
        upstream = str(Path(udtools.__file__).resolve().parent.parent)
    except (ImportError, TypeError, AttributeError) as exc:
        raise PrerequisiteMissing("the official udtools validator is not installed") from exc
    selected = [file.relative_to(root).as_posix() for file in paths]
    official_args = {"working_tree_path": str(root), "file_paths": selected,
                     "ud_context_path": args.get("ud_context_path"), "options": args.get("options")}
    official = _project_child("official", official_args, upstream)
    project = _project_child("project", {**args, "file_paths": selected}, upstream)
    provenance = project.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("source_sha256") != source_hash or provenance.get("validator_module_path") != source.relative_to(root).as_posix() or provenance.get("validator_class_name") != cls:
        raise WorkerError("PROJECT_VALIDATOR_FAILED", "project validation provenance did not match the selected module")
    return {"passed": official["passed"] and project["passed"], "official": official, "project": project,
            "scope": {"file_paths": selected}, "provenance": provenance,
            "coverage": {"content": "completed", "project_rules": "completed"},
            "limitations": ["Official and project checks use distinct processes; hostile project code requires separately admitted OCI jobs."]}
