"""
Unit tests for the ASTAnalyzer.
These tests run with no network or API dependencies.
"""
import pytest
from scanner.ast_analyzer import ASTAnalyzer


@pytest.fixture
def analyzer():
    return ASTAnalyzer()


class TestCommandInjection:
    def test_detects_os_system_with_variable(self, analyzer):
        code = "import os\ncmd = 'ls'; os.system(cmd)"
        findings = analyzer.analyze_file("test.py", code)
        ids = [f["id"] for f in findings]
        assert "command_injection" in ids

    def test_detects_os_system_with_fstring(self, analyzer):
        code = "import os\nuser = 'admin'\nos.system(f'echo {user}')"
        findings = analyzer.analyze_file("test.py", code)
        ids = [f["id"] for f in findings]
        assert "command_injection" in ids

    def test_detects_os_system_with_format(self, analyzer):
        code = "import os\nuser = 'admin'\nos.system('echo {}'.format(user))"
        findings = analyzer.analyze_file("test.py", code)
        ids = [f["id"] for f in findings]
        assert "command_injection" in ids

    def test_does_not_flag_constant_string(self, analyzer):
        # A constant literal string is not dynamic — no injection risk
        code = "import os\nos.system('ls -la')"
        findings = analyzer.analyze_file("test.py", code)
        cmd_findings = [f for f in findings if f["id"] == "command_injection"]
        assert len(cmd_findings) == 0


class TestSQLInjection:
    def test_detects_execute_with_variable(self, analyzer):
        code = (
            "import sqlite3\n"
            "conn = sqlite3.connect(':memory:')\n"
            "cursor = conn.cursor()\n"
            "query = 'SELECT * FROM users WHERE id = 1'\n"
            "cursor.execute(query)"
        )
        findings = analyzer.analyze_file("test.py", code)
        ids = [f["id"] for f in findings]
        assert "sql_injection" in ids

    def test_detects_execute_with_fstring(self, analyzer):
        code = (
            "conn = None\n"
            "user_id = 1\n"
            "conn.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        )
        findings = analyzer.analyze_file("test.py", code)
        ids = [f["id"] for f in findings]
        assert "sql_injection" in ids


class TestInvalidCode:
    def test_handles_syntax_error_gracefully(self, analyzer):
        bad_code = "def foo(:\n    pass"
        findings = analyzer.analyze_file("bad.py", bad_code)
        # Should return an empty list, not raise
        assert findings == []
