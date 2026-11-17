"""Construct Perl invocations solely from bootstrap-verified owned runtime paths."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
from .errors import PrerequisiteMissing

OCI_ROOT=Path('/opt/ud-agent/perl')


def oci_runtime() -> dict | None:
    """Read only the fixed immutable image receipt, never a project pathname."""
    receipt=OCI_ROOT/'runtime.json'
    if not receipt.exists():
        return None
    try:
        if receipt.is_symlink()or not receipt.is_file()or receipt.stat().st_size>16384:
            raise ValueError('unsafe image Perl receipt')
        value=json.loads(receipt.read_bytes())
        if value.get('schema_version')!=1 or set(value)!={'schema_version','executable','library_dirs','loader'}:
            raise ValueError('invalid image Perl receipt')
        def confined(name):
            if not isinstance(name,str)or'\\'in name or':'in name or'\0'in name or any(part in('','.','..')for part in name.split('/')):
                raise ValueError('unsafe image Perl path')
            path=OCI_ROOT/name
            if path.is_symlink()or OCI_ROOT not in path.resolve(strict=True).parents:
                raise ValueError('unconfined image Perl path')
            return str(path)
        libraries=value['library_dirs'];loader=value['loader']
        if not isinstance(libraries,list)or not 1<=len(libraries)<=64 or len(set(libraries))!=len(libraries)or not isinstance(loader,dict)or set(loader)!={'executable','library_dirs'}or not isinstance(loader['library_dirs'],list)or not 1<=len(loader['library_dirs'])<=64:
            raise ValueError('incomplete image Perl closure')
        return {'executable':confined(value['executable']),'library_dirs':[confined(name)for name in libraries],'loader':{'executable':confined(loader['executable']),'library_dirs':[confined(name)for name in loader['library_dirs']]}}
    except (ValueError,KeyError,TypeError,OSError)as error:
        raise PrerequisiteMissing('immutable OCI Perl receipt is invalid or unavailable')from error


def directories(raw: str, label: str) -> list[str]:
    try:
        values=json.loads(raw)
        if (not isinstance(values,list) or not 1<=len(values)<=64 or len(set(values))!=len(values)
                or any(not isinstance(value,str) or '\0' in value or not Path(value).is_absolute() or not Path(value).is_dir() for value in values)):
            raise ValueError(label)
    except (ValueError,TypeError,OSError) as error:
        raise PrerequisiteMissing(label+' inventory is invalid or unavailable') from error
    return values


def command(perl: Path, bridge: Path, tools: Path) -> list[str]:
    libraries=os.environ.get('UD_AGENT_PERL_LIB_PATHS')
    image=oci_runtime()if libraries is None else None
    if image:
        perl=Path(image['executable'])
        libraries=json.dumps(image['library_dirs'])
    if libraries is None:
        # OCI core paths are immutable image contents. Explicit private packs
        # always take the replacement path below, including owned core modules.
        arguments=[str(perl),'-f','-I',str(tools)]
        interset=Path('/opt/ud-agent/interset/lib')
        if interset.is_dir():arguments+=['-I',str(interset)]
        arguments.append(str(bridge))
    else:
        values=list(dict.fromkeys([str(tools),*directories(libraries,'private Perl library')]))
        # BEGIN executes before any bridge `use`/`require`: never parse a JSON
        # receipt by first resolving JSON::PP through an ambient @INC.
        bootstrap='BEGIN { @INC = splice(@ARGV, 0, '+str(len(values))+'); } do shift(@ARGV); die $@ if $@;'
        arguments=[str(perl),'-f','-e',bootstrap,*values,str(bridge)]
    loader=os.environ.get('UD_AGENT_PERL_LOADER')
    loader_libraries=os.environ.get('UD_AGENT_PERL_LOADER_LIB_PATHS')
    if image:
        loader=image['loader']['executable'];loader_libraries=json.dumps(image['loader']['library_dirs'])
    if loader is None:
        if loader_libraries is not None:raise PrerequisiteMissing('private Perl loader executable is missing')
    else:
        if (sys.platform!='linux' or not isinstance(loader_libraries,str) or '\0' in loader
                or not Path(loader).is_absolute() or not Path(loader).is_file() or not os.access(loader,os.X_OK)):
            raise PrerequisiteMissing('private Perl ELF loader is unavailable')
        values=directories(loader_libraries,'private Perl loader library')
        arguments=[loader,'--inhibit-cache','--library-path',os.pathsep.join(values),*arguments]
    return arguments
