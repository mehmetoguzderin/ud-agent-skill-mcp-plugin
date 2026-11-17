"""Bind dynamically loaded script trampolines to their scheduled source path.

Tests and build modules load hyphenated Python scripts with spec_from_file_location.
Its arbitrary import alias is not mutmut's path-derived mutant identity. The
adapter changes instrumentation metadata only, using the verified generated file
path; the pinned upstream trampoline still chooses and executes every mutation.
"""
from pathlib import Path


def install(root):
    import mutmut.mutation.trampoline as trampoline
    from mutmut.utils.format_utils import get_mutant_name
    root = Path(root).resolve(strict=True)
    original = trampoline.wrap_in_trampoline

    def bound_wrapper(mutants_dict, is_classmethod=False):
        def decorate(function):
            generated = Path(function.__code__.co_filename).resolve(strict=True)
            relative = generated.relative_to(root / 'mutants')
            if relative.parts[0] not in ('src', 'scripts') or generated.is_symlink():
                raise ValueError('Mutation trampoline is outside its owned generated source')
            canonical = get_mutant_name(relative, 'x_bound__mutmut_orig').rsplit('.', 1)[0]
            # Bind the decorated function and any values already declared.
            # Preserve module globals: exec'd scripts must still observe their
            # real __name__ (including __main__). Later definitions may honestly
            # retain an import alias; complete-suite dispatch uses no hit subset.
            for candidate in [function, *mutants_dict.values()]:
                candidate.__module__ = canonical
            return original(mutants_dict, is_classmethod)(function)
        return decorate

    trampoline.wrap_in_trampoline = bound_wrapper
