"""
SonarAI — Iteration 2 Tests
Tests for rag_store.py and sonar_rescan.py

Fixes vs original:
  - Removed importlib.reload() calls that were resetting module-level globals
    (_collection, _embed_fn) and breaking @patch decorators.
  - Now patches rag_store._embed and rag_store._get_collection directly,
    which is the correct granularity for these unit tests.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch


# ── RAG Store tests ───────────────────────────────────────────────────────────

class TestRagStore(unittest.TestCase):
    """Tests for rag_store module with ChromaDB mocked out."""

    def _make_mock_collection(self, count=0):
        coll = MagicMock()
        coll.count.return_value = count
        coll.query.return_value = {
            "documents": [[]],
            "metadatas": [[]],
            "distances": [[]],
        }
        return coll

    @patch("rag_store._embed", return_value=[0.1] * 768)
    @patch("rag_store._get_collection")
    def test_retrieve_empty_collection(self, mock_col, mock_embed):
        """Returns [] when collection is empty (count=0, query returns empty lists)."""
        mock_col.return_value = self._make_mock_collection(count=0)

        import rag_store
        result = rag_store.retrieve_similar_fixes("java:S2259", "context", "message")
        self.assertEqual(result, [])

    @patch("rag_store._embed", return_value=[0.1] * 768)
    @patch("rag_store._get_collection")
    def test_retrieve_returns_results_above_threshold(self, mock_col, mock_embed):
        """Returns results with similarity >= 0.3 (distance=0.2 → similarity=0.8)."""
        coll = self._make_mock_collection(count=2)
        coll.query.return_value = {
            "documents": [["doc1"]],
            "metadatas": [[{
                "rule_key": "java:S2259",
                "patch_hunks": "--- a/Foo.java\n+++ b/Foo.java",
                "reasoning": "added null check",
                "confidence": "0.9",
                "file_name": "Foo.java",
                "message": "NPE risk",
            }]],
            "distances": [[0.2]],  # similarity = 1 - 0.2 = 0.8 → above 0.3 threshold
        }
        mock_col.return_value = coll

        import rag_store
        result = rag_store.retrieve_similar_fixes("java:S2259", "context", "message")
        self.assertEqual(len(result), 1)
        self.assertGreaterEqual(result[0]["similarity"], 0.3)
        self.assertEqual(result[0]["rule_key"], "java:S2259")
        self.assertAlmostEqual(result[0]["similarity"], 0.8, places=2)

    @patch("rag_store._embed", return_value=[0.1] * 768)
    @patch("rag_store._get_collection")
    def test_retrieve_filters_low_similarity(self, mock_col, mock_embed):
        """Filters out results with similarity < 0.3 (distance=0.8 → similarity=0.2)."""
        coll = self._make_mock_collection(count=1)
        coll.query.return_value = {
            "documents": [["doc1"]],
            "metadatas": [[{
                "rule_key": "java:S106",
                "patch_hunks": "",
                "reasoning": "",
                "confidence": "0.5",
                "file_name": "Bar.java",
                "message": "",
            }]],
            "distances": [[0.8]],  # similarity = 1 - 0.8 = 0.2 < 0.3 → filtered out
        }
        mock_col.return_value = coll

        import rag_store
        result = rag_store.retrieve_similar_fixes("java:S2259", "context", "msg")
        self.assertEqual(result, [])

    @patch("rag_store._get_collection")
    def test_retrieve_no_rag_when_collection_unavailable(self, mock_col):
        """Returns empty list when ChromaDB is unavailable."""
        mock_col.return_value = None

        import rag_store
        result = rag_store.retrieve_similar_fixes("java:S2259", "ctx", "msg")
        self.assertEqual(result, [])

    @patch("rag_store._get_collection")
    def test_store_skips_when_collection_unavailable(self, mock_col):
        """store_fix returns False when ChromaDB unavailable."""
        mock_col.return_value = None

        import rag_store
        result = rag_store.store_fix("java:S2259", "ctx", "msg", "patch", "reason", 0.9, "Foo.java")
        self.assertFalse(result)

    @patch("rag_store._embed", return_value=[0.1] * 768)
    @patch("rag_store._get_collection")
    def test_store_calls_upsert(self, mock_col, mock_embed):
        """store_fix calls collection.upsert with correct metadata."""
        coll = self._make_mock_collection(count=0)
        mock_col.return_value = coll

        import rag_store
        result = rag_store.store_fix(
            "java:S2259", "context", "NPE message",
            "--- a/Foo.java\n+++ b/Foo.java\n@@ -1,3 +1,4 @@",
            "Added null check", 0.92, "Foo.java"
        )
        self.assertTrue(result)
        coll.upsert.assert_called_once()
        call_kwargs = coll.upsert.call_args[1]
        self.assertEqual(call_kwargs["metadatas"][0]["rule_key"], "java:S2259")
        self.assertEqual(call_kwargs["metadatas"][0]["file_name"], "Foo.java")

    def test_collection_stats_unavailable(self):
        """collection_stats returns available=False when ChromaDB not set up."""
        with patch("rag_store._get_collection", return_value=None):
            import rag_store
            stats = rag_store.collection_stats()
            self.assertFalse(stats["available"])
            self.assertEqual(stats["count"], 0)


# ── Sonar Rescan tests ─────────────────────────────────────────────────────────

class TestSonarRescan(unittest.TestCase):
    """Tests for sonar_rescan module with HTTP calls mocked."""

    @patch("sonar_rescan.settings")
    def test_skips_when_no_token(self, mock_settings):
        """Returns (None, skipped message) when SONAR_TOKEN is not configured."""
        mock_settings.sonar_token = ""
        mock_settings.sonar_host_url = "https://sonarcloud.io"

        import sonar_rescan
        ok, msg = sonar_rescan.rescan_issue("issue-key-123", "project:Foo.java")
        self.assertIsNone(ok)
        self.assertIn("SONAR_TOKEN", msg)

    @patch("sonar_rescan.settings")
    def test_skips_when_no_host(self, mock_settings):
        """Returns (None, skipped message) when SONAR_HOST_URL is not configured."""
        mock_settings.sonar_token = "squ_token"
        mock_settings.sonar_host_url = ""

        import sonar_rescan
        ok, msg = sonar_rescan.rescan_issue("issue-key-123", "project:Foo.java")
        self.assertIsNone(ok)

    def test_project_key_extraction(self):
        """_project_key_from_component extracts project key correctly."""
        import sonar_rescan
        self.assertEqual(
            sonar_rescan._project_key_from_component("my-project:src/main/java/Foo.java"),
            "my-project"
        )
        self.assertEqual(
            sonar_rescan._project_key_from_component("standalone-key"),
            "standalone-key"
        )

    @patch("sonar_rescan.requests.get")
    @patch("sonar_rescan.settings")
    def test_issue_still_open_true(self, mock_settings, mock_get):
        """_issue_still_open returns True when issue appears in search results."""
        mock_settings.sonar_token = "squ_token"
        mock_settings.sonar_host_url = "https://sonarcloud.io"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"total": 1, "issues": [{"key": "issue-123"}]}
        mock_get.return_value = mock_resp

        import sonar_rescan
        result = sonar_rescan._issue_still_open("issue-123")
        self.assertTrue(result)

    @patch("sonar_rescan.requests.get")
    @patch("sonar_rescan.settings")
    def test_issue_still_open_false(self, mock_settings, mock_get):
        """_issue_still_open returns False when issue is resolved."""
        mock_settings.sonar_token = "squ_token"
        mock_settings.sonar_host_url = "https://sonarcloud.io"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"total": 0, "issues": []}
        mock_get.return_value = mock_resp

        import sonar_rescan
        result = sonar_rescan._issue_still_open("issue-123")
        self.assertFalse(result)

    @patch("sonar_rescan.requests.get")
    @patch("sonar_rescan.settings")
    def test_issue_still_open_api_error(self, mock_settings, mock_get):
        """_issue_still_open returns None on API error."""
        mock_settings.sonar_token = "squ_token"
        mock_settings.sonar_host_url = "https://sonarcloud.io"
        mock_get.side_effect = Exception("connection refused")

        import sonar_rescan
        result = sonar_rescan._issue_still_open("issue-123")
        self.assertIsNone(result)


# ── Prompts RAG formatter tests ───────────────────────────────────────────────

class TestRagContextFormatter(unittest.TestCase):
    """Tests for format_rag_context in prompts.py."""

    def test_empty_fixes_returns_empty_string(self):
        from prompts import format_rag_context
        result = format_rag_context([])
        self.assertEqual(result, "")

    def test_formats_single_fix(self):
        from prompts import format_rag_context
        fixes = [{
            "rule_key": "java:S2259",
            "file_name": "Foo.java",
            "similarity": 0.85,
            "reasoning": "Added null check before dereference",
            "patch_hunks": "-    return x.length();\n+    if (x == null) return 0;\n+    return x.length();",
        }]
        result = format_rag_context(fixes)
        self.assertIn("Prior Fix Examples", result)
        self.assertIn("java:S2259", result)
        self.assertIn("Foo.java", result)
        self.assertIn("0.85", result)

    def test_formats_multiple_fixes(self):
        from prompts import format_rag_context
        fixes = [
            {"rule_key": "java:S2259", "file_name": "A.java", "similarity": 0.9,
             "reasoning": "fix 1", "patch_hunks": "patch1"},
            {"rule_key": "java:S2259", "file_name": "B.java", "similarity": 0.7,
             "reasoning": "fix 2", "patch_hunks": "patch2"},
        ]
        result = format_rag_context(fixes)
        self.assertIn("Example 1", result)
        self.assertIn("Example 2", result)


# ── State IssueResult tests ───────────────────────────────────────────────────

class TestIssueResult(unittest.TestCase):
    """Tests for IssueResult TypedDict structure."""

    def test_issue_result_fields(self):
        from state import IssueResult
        result: IssueResult = {
            "issue_key": "AY123",
            "rule_key": "java:S2259",
            "severity": "CRITICAL",
            "file_path": "/repo/src/Foo.java",
            "line": 42,
            "outcome": "pr_opened",
            "pr_url": "https://github.com/org/repo/pull/1",
            "escalation_path": None,
            "confidence": 0.91,
            "sonar_rescan_ok": True,
            "error": None,
        }
        self.assertEqual(result["outcome"], "pr_opened")
        self.assertTrue(result["sonar_rescan_ok"])

    def test_rag_context_fields(self):
        from state import RAGContext
        ctx: RAGContext = {
            "rule_key": "java:S2259",
            "similar_fixes": [{"patch_hunks": "diff", "similarity": 0.8}],
            "retrieved_count": 1,
        }
        self.assertEqual(ctx["retrieved_count"], 1)


if __name__ == "__main__":
    unittest.main()
