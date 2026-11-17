"""Verify automatic full CI and selective manual CI provisioning."""

from pathlib import Path
import json
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]


class CIProvisioningTests(unittest.TestCase):
    def test_only_linux_arm_mutation_waits_for_sdk_and_all_native_rows_share_steps(self):
        workflow=yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        jobs=workflow['jobs'];native=jobs['native'];arm=jobs['native-arm']
        self.assertEqual(set(jobs),{'mutation-sdk','native','native-arm','node24'})
        self.assertNotIn('needs',native);self.assertNotIn('needs',jobs['node24'])
        self.assertEqual(arm['needs'],'mutation-sdk')
        self.assertEqual(arm['strategy']['matrix']['target'],['linux-arm64'])
        self.assertEqual(native['strategy']['matrix']['target'],'''${{ fromJSON(inputs.native_targets || '["linux-x64","macos-arm64","windows-x64","windows-arm64"]') }}''')
        self.assertIs(native['steps'],arm['steps'])
        for job in (native,arm):
            self.assertEqual(job['name'],'${{ matrix.target }}')
            self.assertFalse(job['strategy']['fail-fast'])
        self.assertEqual(native['timeout-minutes'],"${{ startsWith(matrix.target, 'windows-') && 60 || 45 }}")
        self.assertEqual(arm['timeout-minutes'],45)

    def test_all_native_targets_remain_explicit(self):
        workflow=yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        jobs=workflow['jobs']; native=jobs['native']
        runners=json.loads(re.fullmatch(r"\$\{\{ fromJSON\('(.+)'\)\[matrix.target\] \}\}",native['runs-on']).group(1))
        self.assertEqual(runners,{'linux-x64':'ubuntu-26.04','macos-arm64':'macos-26','windows-x64':'windows-2025-vs2026','windows-arm64':'windows-11-vs2026-arm'})
        self.assertEqual(jobs['native-arm']['runs-on'],'ubuntu-26.04-arm')
        # PyYAML's YAML 1.1 loader interprets the unquoted GitHub key `on` as True.
        triggers=workflow.get('on',workflow.get(True))
        self.assertEqual(set(triggers),{'push','pull_request','workflow_dispatch'})
        self.assertEqual(triggers['push'],{'branches':['main']})
        self.assertEqual(triggers['pull_request'],{'branches':['main']})
        inputs=triggers['workflow_dispatch']['inputs']
        self.assertEqual(set(json.loads(inputs['native_targets']['default'])),set(runners))
        self.assertTrue(inputs['linux_arm64']['default']); self.assertTrue(inputs['node24']['default'])
        self.assertEqual(native['if'],'''${{ toJSON(fromJSON(inputs.native_targets || '["linux-x64","macos-arm64","windows-x64","windows-arm64"]')) != '[]' }}''')
        self.assertEqual(jobs['node24']['if'],"github.event_name != 'workflow_dispatch' || inputs.node24")
        self.assertEqual(jobs['mutation-sdk']['if'],"(github.event_name != 'workflow_dispatch' || inputs.linux_arm64) && inputs.sdk_run_id == ''")
        self.assertEqual(jobs['native-arm']['if'],"${{ !cancelled() && (github.event_name != 'workflow_dispatch' || inputs.linux_arm64) && (needs.mutation-sdk.result == 'success' || inputs.sdk_run_id != '') }}")

    def test_every_test_job_provisions_locked_python_before_tests(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        jobs = ci.split('  native:\n', 1)[1].split('  node24:\n', 1)
        self.assertEqual(len(jobs), 2)
        for job, python_version in zip(jobs, ('3.15.2', '3.14.10'), strict=True):
            self.assertIn('astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2', job)
            self.assertIn("version: '0.13.7'", job)
            self.assertIn('enable-cache: false', job)
            self.assertLess(job.index(f'uv sync --locked --all-groups --managed-python --python {python_version}'), job.index('run: npm run test:mutation' if 'run: npm run test:mutation' in job else 'run: npm test'))
        self.assertNotIn('  mutation:\n', ci)
        self.assertNotIn('npm run check', ci)
        self.assertNotIn('cargo install cargo-mutants', ci)

    def test_bounded_mutation_replaces_only_the_matching_native_original_profile(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        native = ci.split('  native:\n', 1)[1].split('  node24:\n', 1)[0]
        self.assertIn("if: matrix.target == 'linux-arm64'\n        run: npm run test:mutation", native)
        self.assertIn("if: matrix.target != 'linux-arm64'\n        run: npm test", native)
        self.assertEqual(ci.count('run: npm run test:mutation'), 1)
        self.assertEqual(ci.count('run: npm test'), 2)
        self.assertNotIn('--profile bounded', ci)  # The package command already selects it.

    def test_every_test_job_fetches_both_rust_lockfiles_before_offline_tests(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        native, node24 = ci.split('  native:\n', 1)[1].split('  node24:\n', 1)
        for name, job in (('native', native), ('node24', node24)):
            with self.subTest(job=name):
                provision = job.split('      - name: Prefetch locked Rust dependencies\n', 1)[1].split('      - ', 1)[0]
                self.assertIn('shell: bash', provision)
                self.assertNotIn('if:', provision)
                commands = provision.split('run: |\n', 1)[1].strip().splitlines()
                self.assertEqual([command.strip() for command in commands], [
                    'cargo fetch --locked',
                    'cargo fetch --locked --manifest-path scripts/quality/rust-assertion-parser/Cargo.toml',
                ])
                for test in ('run: npm test', 'run: npm run test:mutation'):
                    if test in job:
                        self.assertLess(job.index('Prefetch locked Rust dependencies'), job.index(test))

    def test_sdk_cache_is_verified_before_an_immutable_image_is_used(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        setup, native = ci.split('  mutation-sdk:\n', 1)[1].split('  native:\n', 1)
        self.assertIn('runs-on: ubuntu-26.04-arm', setup)
        self.assertIn('prepare-mutation-runtime.py --ci-cache-key', setup)
        self.assertIn('actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9', setup)
        self.assertIn('key: ud-agent-mutation-sdk-linux-arm64-${{ steps.sdk-key.outputs.key }}', setup)
        self.assertNotIn('restore-keys:', setup)
        self.assertNotIn('cache-hit', setup)  # Restored bytes still pass the verifier.
        self.assertIn('--ensure-ci --asset-root "$PWD/.artifacts/mutation-ci-sdk" --output "$PWD/.artifacts/mutation-ci-context" --download', setup)
        for filename in ('sdk-image.tar', 'ci-sdk.json', 'input-receipt.json'):
            self.assertIn('.artifacts/mutation-ci-sdk/' + filename, setup)
        self.assertIn('needs: mutation-sdk', native)
        self.assertLess(native.index('--load-ci-image'), native.index('run: npm run test:mutation'))
        self.assertIn('run: npm run test:mutation -- --image "${{ steps.mutation-image.outputs.image }}"', native)
        self.assertNotIn('localhost/ud-agent-mutation-runtime', ci)
        self.assertIn('run-id: ${{ inputs.sdk_run_id || github.run_id }}',native)
        self.assertIn('github-token: ${{ github.token }}',native)
        self.assertIn('name: mutation-sdk-linux-arm64-${{ inputs.sdk_run_id || github.run_id }}-${{ inputs.sdk_run_id && inputs.sdk_run_attempt || github.run_attempt }}',native)
        self.assertIn('.artifacts/mutation/**/*.log',native)
        self.assertIn('.artifacts/mutation/runs/*/summary.json',native)


if __name__ == '__main__':
    unittest.main()
