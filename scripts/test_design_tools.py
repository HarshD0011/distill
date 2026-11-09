"""Meaningful boundary checks for offline tooling; no candidate execution."""
import unittest
import json
import tempfile
from pathlib import Path
from offline_common import private_write
from train_classifier import train
from mine_transcripts import commands
from trace_harness import docker_args, observed_effects


class DesignTools(unittest.TestCase):
    def test_sensitive_outputs_are_private_and_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'output.json'
            private_write(path, 'sensitive fixture')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = Path(d) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                private_write(link, 'must not replace the target')
            self.assertEqual(path.read_text(), 'sensitive fixture')

    def test_trace_boundary_has_no_host_mount_network_or_image_pull(self):
        args = docker_args('fixture@sha256:' + 'a' * 64, 'test', 'echo hi')
        for flag in ['--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534']:
            self.assertIn(flag, args)
        self.assertFalse(any(v in args for v in ['--privileged', '-v', '--volume', '--mount', '--network=host']))

    def test_trace_failure_is_not_a_successful_observed_effect(self):
        observed, attempted = observed_effects('1 unlink("x") = -1 EPERM\n2 connect(3, x, 1) = 0\n')
        self.assertNotIn('file_delete', observed)
        self.assertIn('file_delete', attempted)
        self.assertIn('connect', observed)

    def test_mining_only_decodes_literals_without_executing_tool_source(self):
        row = {'payload': {'type': 'custom_tool_call', 'input': 'tools.exec_command({cmd:' + json.dumps("node -e 'console.log(1)'") + '})'}}
        self.assertEqual(len(list(commands(row))), 1)
        self.assertEqual(list(commands({'payload': {'type': 'custom_tool_call', 'input': 'tools.exec_command({cmd:process.env.SECRET})'}})), [])

    def test_classifier_rejects_group_leakage_and_abstains_on_small_samples(self):
        rows = [{'id': 'a', 'reviewed': True, 'split': 'train', 'group': 'one', 'expected_severity': 'low', 'features': {}, 'report': {'command_digest': 'a'}},
                {'id': 'b', 'reviewed': True, 'split': 'test', 'group': 'two', 'expected_severity': 'high', 'features': {}, 'report': {'command_digest': 'b'}}]
        model = train(rows, 20, 0.99)
        self.assertEqual(model['validation']['abstentions'], 1)
        self.assertEqual(model['validation']['predictions'], 0)
        rows[1]['group'] = 'one'
        with self.assertRaises(ValueError):
            train(rows, 1, 0.99)


if __name__ == '__main__':
    unittest.main()
