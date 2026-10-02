"""Historical snapshot at 8b9d85c; updates require explicit preservation review."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import build_site

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / 'tests/fixtures/legacy-source-sha256.json').read_text())
DOWNLOADS = {'Demo-Enable-SoftAP-WinRT.exe', 'Demo-IOCP-WinRT.exe',
             'Demo-QOSAddSocketToFlow.cpp', 'Demo-QOSAddSocketToFlow.exe', 'main.cpp'}


class HistoricalSnapshotTests(unittest.TestCase):
    def test_all_34_historical_files_remain_byte_identical(self):
        self.assertEqual(len(SNAPSHOT), 34)
        for name, expected in SNAPSHOT.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)

    def test_manifest_keeps_every_historical_web_path_not_downloads(self):
        manifest = {line for line in (ROOT / 'site/legacy-files.txt').read_text().splitlines()
                    if line and not line.startswith('#')}
        self.assertEqual(manifest, set(SNAPSHOT) - DOWNLOADS)

    def test_actual_legacy_output_preserves_all_28_nonroot_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            files = build_site._legacy(ROOT, Path(temp) / 'out')
        expected = set(SNAPSHOT) - DOWNLOADS - {'index.html'}
        self.assertEqual(set(files), expected | {'legacy/index.html'})
        for name in expected:
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(files[name]).hexdigest(), SNAPSHOT[name])
        self.assertIn(b'<base href="/">', files['legacy/index.html'])
        self.assertIn(b'/legacy/index.html#Quick-Start', files['legacy/index.html'])


if __name__ == '__main__':
    unittest.main()
