"""Independent protocol and side-effect tests using an explicit udlib fixture.

Pinned upstream repository checks are exercised separately by image acceptance.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
BRIDGE = ROOT / 'workers/ud/src/ud_agent/perl/repository_bridge.pl'
FIXTURE = r'''
package udlib;
sub get_language_hash { return {English => {lcode => 'en'}} }
sub decompose_repo_name { my ($name) = @_; return $name =~ /^UD_([A-Za-z]+)/ ? ($1) : (); }
sub get_ltcode_from_repo_name { return 'en_sample' }
sub check_files {
  my ($root, $folder, $key, $errors, $count) = @_;
  print "fixture upstream log\n";
  push @$errors, "missing split for $key"; $$count++;
}
sub read_readme { my ($folder, $root) = @_; return -f "$root/$folder/README.md" ? {valid => 1} : undef; }
sub check_metadata {
  my ($root, $folder, $metadata, $errors, $count) = @_;
  push @$errors, "metadata checked for $folder"; $$count++;
}
sub check_documentation {
  my ($root, $folder, $code, $errors, $count) = @_;
  if (!-f "$root/docs/_$code/index.md") {push @$errors, 'missing documentation'; $$count++;}
}
1;
'''


class RepositoryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'udlib.pm').write_text(FIXTURE)
        (self.root / 'docs/_en').mkdir(parents=True)
        self.documentation = b'English documentation\n'
        (self.root / 'docs/_en/index.md').write_bytes(self.documentation)
        self.layout = self.root / 'layout'
        (self.layout / 'UD_English-Sample').mkdir(parents=True)

    def call(self, payload=None, *, bootstrap=None, **changes):
        request = {'repository_name': 'UD_English-Sample', 'languages_path': str(self.root / 'languages.yaml'),
                   'layout_root': str(self.layout), 'docs_path': str(self.root / 'docs'),
                   'check_families': ['repository', 'documentation']}
        request.update(changes)
        command = [os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl', '-I', str(self.root)]
        command += ['-e', bootstrap, str(BRIDGE)] if bootstrap else [str(BRIDGE)]
        env = {**os.environ, 'PERL5LIB': '', 'PERL5OPT': ''}
        return subprocess.run(command, input=json.dumps(request).encode() if payload is None else payload, capture_output=True, env=env, timeout=10)

    def test_complete_incidents_and_documentation_staging(self):
        (self.layout / 'UD_English-Sample/README.md').write_text('readable\n')
        result = self.call()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'fixture upstream log\n')
        self.assertEqual(json.loads(result.stdout), {'reports': [
            {'family': 'repository', 'passed': False, 'error_count': 2,
             'incidents': ['missing split for en_sample', 'metadata checked for UD_English-Sample']},
            {'family': 'documentation', 'passed': True, 'error_count': 0, 'incidents': []}]})
        self.assertEqual((self.layout / 'docs/_en/index.md').read_bytes(), self.documentation)

    def test_missing_readme_and_documentation_preserve_all_incidents(self):
        (self.root / 'docs/_en/index.md').unlink()
        result = self.call()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['reports'], [
            {'family': 'repository', 'passed': False, 'error_count': 2,
             'incidents': ['missing split for en_sample', 'Cannot read repository README']},
            {'family': 'documentation', 'passed': False, 'error_count': 1, 'incidents': ['missing documentation']}])

    def test_inherited_text_layers_do_not_translate_protocol_or_bounded_diagnostics(self):
        (self.layout / 'UD_English-Sample/README.md').write_bytes(b'readable\n')
        bootstrap = 'binmode(STDIN, ":crlf"); binmode(STDOUT, ":crlf"); binmode(STDERR, ":crlf"); do $ARGV[0];'
        result = self.call(bootstrap=bootstrap)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'fixture upstream log\n')
        self.assertEqual(json.loads(result.stdout)['reports'][0]['error_count'], 2)

    def test_unknown_language_is_reported_for_each_family(self):
        result = self.call(repository_name='UD_Unknown-Sample')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['reports'], [
            {'family': family, 'passed': False, 'error_count': 1,
             'incidents': ['Unknown repository language in UD_Unknown-Sample']}
            for family in ('repository', 'documentation')])

    def test_unsafe_name_and_unknown_family_reject(self):
        for changes, expected in [({'repository_name': '../UD_English'}, b'invalid repository name'),
                                  ({'check_families': ['other']}, b'invalid repository check family')]:
            with self.subTest(changes=changes):
                result = self.call(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout), {'error': 'repository_execution_failed'})
                self.assertIn(expected, result.stderr)

    def test_request_and_documentation_bounds_are_exact(self):
        for raw in (b'[]', b'"scalar"'):
            result = self.call(raw)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'invalid repository request', result.stderr)
        request = {'repository_name': 'UD_English-Sample', 'languages_path': str(self.root / 'languages.yaml'),
                   'layout_root': str(self.layout), 'docs_path': str(self.root / 'docs'), 'check_families': ['documentation']}
        data = json.dumps(request).encode()
        payload = data + b' ' * (1048576 - len(data))
        self.assertEqual(self.call(payload).returncode, 0)
        rejected = self.call(payload + b' ')
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(b'repository request too large', rejected.stderr)
        path = self.root / 'docs/_en/index.md'
        path.write_bytes(b'x' * 1048576)
        self.assertEqual(self.call(check_families=['documentation']).returncode, 0)
        path.write_bytes(b'x' * 1048577)
        result = self.call(check_families=['documentation'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'documentation input is too large', result.stderr)

    def test_invalid_pinned_language_code_never_creates_a_path(self):
        (self.root / 'udlib.pm').write_text(FIXTURE.replace("lcode => 'en'", "lcode => '../escape'"))
        result = self.call(check_families=['documentation'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'invalid pinned language code', result.stderr)
        self.assertFalse((self.layout / 'docs').exists())

    def test_protocol_setup_and_copy_failures_are_structured_and_bounded(self):
        for fail_at, message in [(1, b'cannot preserve protocol output\n'), (2, b'cannot isolate upstream output\n')]:
            script = r'''BEGIN { my $count=0; *CORE::GLOBAL::open = sub (*;$@) { return 0 if $_[1] eq '>&' && ++$count==FAIL_AT; return CORE::open($_[0],$_[1],$_[2]); }; } do $ARGV[0];'''.replace('FAIL_AT',str(fail_at))
            result = self.call(bootstrap=script)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout), {'error':'repository_execution_failed'})
            self.assertEqual(result.stderr,message)
        script = r'''BEGIN { require File::Copy; no warnings 'redefine'; *File::Copy::copy=sub {0}; } do $ARGV[0];'''
        result = self.call(check_families=['documentation'],bootstrap=script)
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout),{'error':'repository_execution_failed'})
        self.assertEqual(result.stderr,b'cannot stage pinned documentation\n')
        (self.root/'udlib.pm').write_text(FIXTURE.replace("sub get_language_hash { return {English => {lcode => 'en'}} }", "sub get_language_hash { die(('x' x 5000).\"\\n\"); }"))
        result = self.call()
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout),{'error':'repository_execution_failed'})
        self.assertEqual(result.stderr,b'x'*4096)


if __name__ == '__main__':
    unittest.main()
