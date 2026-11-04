"""Offline workflow policy checks; dependencies live only in ci/requirements.txt."""

from copy import deepcopy
import re
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
}


class UniqueLoader(yaml.BaseLoader):
    """YAML 1.2-style scalar strings avoid YAML 1.1's 'on' boolean coercion."""


def mapping(loader, node):
    pairs = loader.construct_pairs(node)
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate YAML key")
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def check_policy(workflow):
    assert workflow['permissions'] == {'contents': 'read'}
    assert set(workflow['on']) == {'push', 'pull_request', 'workflow_dispatch'}
    assert workflow['on']['push'] == {'branches': ['main']}
    assert workflow['on']['pull_request'] == {'branches': ['main']}
    assert set(workflow['jobs']) == {'tests', 'audit', 'secrets'}
    for job in workflow['jobs'].values():
        assert job['runs-on'] == 'ubuntu-24.04'
        assert 0 < int(job['timeout-minutes']) <= 15
        assert not {'permissions', 'environment', 'container', 'services', 'if', 'continue-on-error'}.intersection(job)
        for step in job['steps']:
            assert not {'continue-on-error', 'if'}.intersection(step)
            if 'uses' in step:
                assert step['uses'] in ALLOWED_ACTIONS
                assert re.fullmatch(r'[^@]+@[0-9a-f]{40}', step['uses'])
                if step['uses'].startswith('actions/checkout@'):
                    assert step['with']['persist-credentials'] == 'false'
                if step['uses'].startswith('actions/setup-python@'):
                    assert step['with']['python-version'] == '3.14'
            if 'run' in step:
                assert '${{' not in step['run']  # No event-controlled shell interpolation.
                assert not re.search(r'\|\|\s*true|--fix|--ignore-vuln', step['run'])
    text = str(workflow)
    assert not re.search(r'\$\{\{\s*secrets\.', text)
    assert 'write' not in str(workflow['permissions'])


class WorkflowSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load((ROOT / '.github/workflows/security-ci.yml').read_text(), Loader=UniqueLoader)

    def test_security_policy(self):
        check_policy(self.workflow)

    def test_reject_privileged_trigger(self):
        workflow = deepcopy(self.workflow)
        workflow['on']['pull_request_target'] = {}
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_write_permissions(self):
        workflow = deepcopy(self.workflow)
        workflow['permissions']['contents'] = 'write'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_self_hosted_runner(self):
        workflow = deepcopy(self.workflow)
        workflow['jobs']['tests']['runs-on'] = 'self-hosted'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_unpinned_action(self):
        workflow = deepcopy(self.workflow)
        workflow['jobs']['tests']['steps'][0]['uses'] = 'actions/checkout@main'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_retained_credentials(self):
        workflow = deepcopy(self.workflow)
        workflow['jobs']['tests']['steps'][0]['with']['persist-credentials'] = 'true'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_concealed_failure(self):
        workflow = deepcopy(self.workflow)
        workflow['jobs']['audit']['continue-on-error'] = 'true'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_reject_shell_interpolation(self):
        workflow = deepcopy(self.workflow)
        workflow['jobs']['tests']['steps'][-1]['run'] = 'echo ${{ github.event.pull_request.title }}'
        with self.assertRaises(AssertionError): check_policy(workflow)

    def test_single_full_suite_covers_security_modules(self):
        commands = '\n'.join(step.get('run', '') for job in self.workflow['jobs'].values() for step in job['steps'])
        self.assertEqual(commands.count('-m pytest -q'), 1)
        self.assertIn('-m pip check', commands)
        for name in ('test_authorization.py', 'test_agent_tools.py', 'test_security_telemetry.py',
                     'test_live_prompt_injection.py', 'test_ollama_client.py'):
            self.assertTrue((ROOT / 'tests' / name).is_file())
        self.assertNotIn('--run-live', commands)
        self.assertNotIn('--run-approved-retest', commands)

    def test_audit_is_strict_and_read_only(self):
        commands = '\n'.join(step.get('run', '') for step in self.workflow['jobs']['audit']['steps'])
        self.assertIn('ci/requirements.txt', commands)
        self.assertIn('pip_audit --strict', commands)
        self.assertIn('--no-deps --disable-pip -r requirements.txt', commands)
        self.assertNotIn('--fix', commands)

    def test_full_history_secret_scan(self):
        checkout = self.workflow['jobs']['secrets']['steps'][0]
        self.assertEqual(checkout['with']['fetch-depth'], '0')
        commands = '\n'.join(step.get('run', '') for step in self.workflow['jobs']['secrets']['steps'])
        self.assertIn('ci/scan_secrets.py', commands)

    def test_dependency_files_are_exact_pins(self):
        for name in ('requirements.txt', 'ci/requirements.txt'):
            for line in (ROOT / name).read_text().splitlines():
                if line.strip() and not line.startswith('#'):
                    self.assertRegex(line, r'^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+$')

    def test_duplicate_yaml_keys_rejected(self):
        with self.assertRaises(ValueError):
            yaml.load('permissions: read\npermissions: write\n', Loader=UniqueLoader)


if __name__ == '__main__':
    unittest.main()
