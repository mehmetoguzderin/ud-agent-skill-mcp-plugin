"""Build-time binding to the shared bounded worker ELF implementation."""
import importlib.util
from pathlib import Path
_path=Path(__file__).resolve().parents[2]/'workers/ud/src/ud_agent/elf_runtime.py'
_spec=importlib.util.spec_from_file_location('ud_shared_elf_runtime',_path)
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
inspect=_module.inspect
without_search_paths=_module.without_search_paths
with_interpreter=_module.with_interpreter
