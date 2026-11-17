"""OCI layers remain opaque data, with independent overlay/link expectations."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('ud_test_oci_filesystem',ROOT/'scripts/runtime/oci_filesystem.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def layer(entries):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as archive:
        for name,kind,value in entries:
            member=tarfile.TarInfo(name)
            if kind=='file':member.size=len(value);archive.addfile(member,io.BytesIO(value))
            else:
                member.type={'dir':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'device':tarfile.CHRTYPE}[kind]
                if kind in ('symlink','hardlink'):member.linkname=value
                archive.addfile(member)
    stream.seek(0)
    return tarfile.open(fileobj=stream,mode='r:')


class OciFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
        self.filesystem=module.Filesystem(self.root/'opaque')

    def add(self,*entries):
        with layer(entries) as archive:self.filesystem.add_layer(archive)

    def test_regular_files_and_root_relative_links_resolve_only_to_opaque_owned_bytes(self):
        self.add(('usr','dir',''),('usr/lib','dir',''),('usr/lib/a.so','file',b'independent'),('lib','symlink','usr/lib'),('alias','hardlink','usr/lib/a.so'))
        for name in ['usr/lib/a.so','/lib/a.so','alias']:
            canonical,file=self.filesystem.resolve(name)
            self.assertEqual(canonical,'usr/lib/a.so');self.assertEqual(file.read_bytes(),b'independent');self.assertEqual(file.parent,self.root/'opaque')
        self.assertEqual([path.name for path in(self.root/'opaque').iterdir()],['0'])
        self.assertEqual(self.filesystem.resolve('usr/lib',True),('usr/lib',None))

    def test_relative_symlinks_cannot_leave_the_logical_root_or_follow_host_files(self):
        self.add(('usr/share/a.so','file',b'logical'),('usr/lib/a.so','symlink','../share/a.so'),('escape','symlink','../../etc/passwd'),('host','symlink','/etc/passwd'),('a','symlink','b'),('b','symlink','a'),('device','device',''))
        self.assertEqual(self.filesystem.resolve('usr/lib/a.so')[1].read_bytes(),b'logical')
        for name in ['escape','host','a','device']:
            with self.assertRaises(ValueError):self.filesystem.resolve(name)
        self.assertFalse((self.root/'etc').exists())

    def test_whiteouts_remove_only_lower_entries_and_opaque_directories_keep_new_content(self):
        self.add(('d','dir',''),('d/old','file',b'old'),('d/replaced','file',b'old'),('keep','file',b'keep'))
        self.add(('d/new','file',b'new'),('d/replaced','file',b'new'),('d/.wh..wh..opq','file',b''))
        with self.assertRaises(ValueError):self.filesystem.resolve('d/old')
        self.assertEqual(self.filesystem.resolve('d',True),('d',None))
        self.assertEqual(self.filesystem.resolve('d/new')[1].read_bytes(),b'new')
        self.assertEqual(self.filesystem.resolve('d/replaced')[1].read_bytes(),b'new')
        self.assertEqual(self.filesystem.resolve('keep')[1].read_bytes(),b'keep')
        self.add(('.wh.keep','file',b''))
        with self.assertRaises(ValueError):self.filesystem.resolve('keep')

    def test_root_opaque_and_replaced_parent_never_leave_reachable_lower_children(self):
        self.add(('a','file',b'old'),('dir','dir',''),('dir/child','file',b'old'))
        self.add(('fresh','file',b'fresh'),('.wh..wh..opq','file',b''))
        with self.assertRaises(ValueError):self.filesystem.resolve('a')
        with self.assertRaises(ValueError):self.filesystem.resolve('dir/child')
        self.assertEqual(self.filesystem.resolve('fresh')[1].read_bytes(),b'fresh')
        self.add(('dir','dir',''),('dir/child','file',b'old'))
        self.add(('dir','file',b'parent'))
        with self.assertRaises(ValueError):self.filesystem.resolve('dir/child')

    def test_traversal_empty_whiteouts_and_excessive_members_are_rejected(self):
        for name in ['../outside','/absolute','bad\\name','x/../y','.wh.']:
            with self.assertRaises(ValueError):self.add((name,'file',b'bad'))
        self.assertFalse((self.root/'outside').exists())
        with layer([('huge','file',b'x')]) as archive:
            self.filesystem.total=4*1024**3
            with self.assertRaises(ValueError):self.filesystem.add_layer(archive)

    def test_observer_retains_every_shipped_ordinary_file_before_replacement_or_whiteout(self):
        observed=[];self.filesystem.file_observer=lambda name,file,serial:observed.append((name,file.read_bytes(),serial))
        self.add(('bin/tool','file',b'first'),('bin/tool','file',b'second'),('retired','file',b'old payload'))
        self.add(('bin/tool','file',b'final'),('.wh.retired','file',b''))
        self.assertEqual(observed,[('bin/tool',b'first',0),('bin/tool',b'second',1),('retired',b'old payload',2),('bin/tool',b'final',3)])
        self.assertEqual(self.filesystem.resolve('bin/tool')[1].read_bytes(),b'final')
        with self.assertRaises(ValueError):self.filesystem.resolve('retired')


if __name__=='__main__':unittest.main()
