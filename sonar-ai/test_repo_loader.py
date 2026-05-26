"""Tests for repo_loader (offline — no git clone required)."""

import tempfile
from pathlib import Path

import pytest

from repo_loader import resolve_java_file, extract_method_context, _repo_name_from_url, _inject_token


SAMPLE_JAVA = """\
package com.example;

import java.util.Objects;

public class UserService {

    private UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public String getUserName(Long id) {
        User user = repo.findById(id).orElse(null);
        // sonar flags line below: possible NPE
        return user.getName();
    }

    public void doOtherStuff() {
        System.out.println("hello");
    }
}
"""


@pytest.fixture()
def java_repo(tmp_path):
    """Create a minimal fake Java repository tree."""
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "UserService.java").write_text(SAMPLE_JAVA)
    (src / "FileProcessor.java").write_text("public class FileProcessor {}")
    return tmp_path


class TestResolveJavaFile:
    def test_direct_path_resolution(self, java_repo):
        component = "my-project:src/main/java/com/example/UserService.java"
        result = resolve_java_file(str(java_repo), component)
        assert result is not None
        assert "UserService.java" in result

    def test_rglob_fallback(self, java_repo):
        # Component with wrong prefix but correct filename
        component = "other-key:wrong/path/UserService.java"
        result = resolve_java_file(str(java_repo), component)
        assert result is not None
        assert "UserService.java" in result

    def test_missing_file_returns_none(self, java_repo):
        component = "proj:src/main/java/Nonexistent.java"
        result = resolve_java_file(str(java_repo), component)
        assert result is None

    def test_component_without_prefix(self, java_repo):
        component = "src/main/java/com/example/UserService.java"
        result = resolve_java_file(str(java_repo), component)
        assert result is not None


class TestExtractMethodContext:
    def test_returns_string(self, java_repo):
        file_path = str(java_repo / "src" / "main" / "java" / "com" / "example" / "UserService.java")
        context = extract_method_context(file_path, 16)
        assert isinstance(context, str)
        assert len(context) > 0

    def test_context_contains_flagged_line(self, java_repo):
        file_path = str(java_repo / "src" / "main" / "java" / "com" / "example" / "UserService.java")
        context = extract_method_context(file_path, 16)
        # Line 16 is inside getUserName — check method name appears
        assert "getUserName" in context or "user" in context.lower()

    def test_fallback_for_invalid_line(self, java_repo):
        file_path = str(java_repo / "src" / "main" / "java" / "com" / "example" / "UserService.java")
        # Line 999 doesn't exist — raw slice fallback
        context = extract_method_context(file_path, 999)
        assert isinstance(context, str)


class TestHelpers:
    def test_repo_name_from_https_url(self):
        assert _repo_name_from_url("https://github.com/owner/my-repo.git") == "my-repo"
        assert _repo_name_from_url("https://github.com/owner/my-repo") == "my-repo"

    def test_inject_token(self):
        url = "https://github.com/owner/repo.git"
        result = _inject_token(url, "ghp_abc123")
        assert "x-access-token:ghp_abc123@" in result

    def test_inject_token_empty_token(self):
        url = "https://github.com/owner/repo.git"
        result = _inject_token(url, "")
        assert result == url
