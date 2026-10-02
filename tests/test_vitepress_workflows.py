"""Installed deployment workflows keep the private-review boundary; no hosted writes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VitePressWorkflowTests(unittest.TestCase):
    def test_pages_builds_and_tests_before_isolated_upload(self):
        text = (ROOT / '.github/workflows/wiki-pages.yml').read_text()
        steps = ["npm ci", "python3 -m unittest discover -s tests -v",
                 "python3 scripts/content.py", "npm test", "npm run build",
                 "scripts/audit_site.py --output _site", "actions/upload-pages-artifact@"]
        offsets = [text.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('path: _site', text)
        self.assertIn("node-version: '22'", text)
        self.assertIn("github.repository == 'forecs/forecs.github.io'", text)
        self.assertIn("github.event.repository.default_branch == 'master'", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertEqual(text.count("vars.WIKI_PAGES_ENABLED == 'true'"), 2)
        build, deploy = text.split('  deploy:', 1)
        self.assertNotIn('pages: write', build)
        self.assertNotIn('id-token: write', build)
        self.assertIn('pages: write', deploy)
        self.assertIn('id-token: write', deploy)
        self.assertIn('name: github-pages', deploy)

    def test_pr_checks_only_use_synthetic_builds_without_deployment(self):
        text = (ROOT / '.github/workflows/wiki-checks.yml').read_text()
        self.assertIn('npm ci', text)
        self.assertIn('npm test', text)
        self.assertIn('synthetic fixtures only', text)
        for forbidden in ('npm run build', 'upload-artifact@', 'upload-pages-artifact@',
                          'deploy-pages@', 'pull_request_target:', 'secrets.',
                          'pages: write', 'id-token: write', 'contents: write'):
            self.assertNotIn(forbidden, text)



class ModernOnlyRepositoryTests(unittest.TestCase):
    def test_all_historical_files_deleted(self):
        names = (ROOT / 'docs/legacy-deleted-files.txt').read_text().splitlines()
        self.assertEqual(len(names), 34)
        for name in names:
            self.assertFalse((ROOT / name).exists(), name)
        for name in ('site/legacy-files.txt', 'workflow-templates/wiki-pages.yml',
                     'workflow-templates/wiki-checks.yml', 'site/frontend/archive/index.md',
                     'tests/fixtures/legacy-source-sha256.json'):
            self.assertFalse((ROOT / name).exists(), name)

    def test_checks_include_branch_and_actionlint(self):
        text = (ROOT / '.github/workflows/wiki-checks.yml').read_text()
        self.assertIn('openclaw/vitepress-blog-modernization', text)
        self.assertIn('actionlint@v1.7.7', text)

    def test_stable_exact_dependency_pins_and_no_dev_server(self):
        import json
        package = json.loads((ROOT / 'package.json').read_text())
        self.assertEqual(package['devDependencies'], {'vitepress': '1.6.4', '@playwright/test': '1.63.0'})
        self.assertNotIn('dev', package['scripts'])
        self.assertNotIn('preview', package['scripts'])


if __name__ == '__main__':
    unittest.main()
