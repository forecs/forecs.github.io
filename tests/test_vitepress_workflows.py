"""Deployment templates keep the private-review boundary; no hosted writes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VitePressWorkflowTests(unittest.TestCase):
    def test_pages_builds_and_tests_before_isolated_upload(self):
        text = (ROOT / 'workflow-templates/wiki-pages.yml').read_text()
        steps = ["npm ci", "python3 -m unittest discover -s tests -v",
                 "python3 scripts/content.py", "npm test", "npm run build",
                 "actions/upload-pages-artifact@"]
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
        text = (ROOT / 'workflow-templates/wiki-checks.yml').read_text()
        self.assertIn('npm ci', text)
        self.assertIn('npm test', text)
        self.assertIn('synthetic fixtures only', text)
        for forbidden in ('npm run build', 'upload-artifact@', 'upload-pages-artifact@',
                          'deploy-pages@', 'pull_request_target:', 'secrets.',
                          'pages: write', 'id-token: write', 'contents: write'):
            self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
