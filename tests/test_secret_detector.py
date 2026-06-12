"""
Unit tests for SecretDetector — no API calls required.
"""
import pytest
from scanner.secret_detector import SecretDetector


@pytest.fixture
def detector():
    return SecretDetector()


class TestEntropyCalculation:
    def test_high_entropy_string(self, detector):
        # Random-looking token should have high entropy
        entropy = detector.calculate_entropy("aB1c2D3e4F5g6H7i8J9k0")
        assert entropy > 3.5

    def test_low_entropy_string(self, detector):
        # Repetitive string has low entropy
        entropy = detector.calculate_entropy("aaaaaaaaaa")
        assert entropy < 1.0

    def test_empty_string(self, detector):
        assert detector.calculate_entropy("") == 0.0


class TestPatternDetection:
    def test_detects_aws_access_key(self, detector):
        code = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        findings = detector.analyze_file("config.py", code)
        ids = [f["id"] for f in findings]
        assert "secret_detected" in ids

    def test_detects_high_entropy_api_key(self, detector):
        code = "MY_SECRET_TOKEN = 'aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q'"
        findings = detector.analyze_file("config.py", code)
        ids = [f["id"] for f in findings]
        assert "high_entropy_secret" in ids

    def test_short_low_entropy_key_not_flagged(self, detector):
        code = "API_KEY = 'short_key'"
        findings = detector.analyze_file("config.py", code)
        assert len(findings) == 0

    def test_no_false_positive_on_normal_string(self, detector):
        code = "greeting = 'hello world'"
        findings = detector.analyze_file("config.py", code)
        assert len(findings) == 0


class TestScanEngine:
    """Integration-style tests for ScanEngine that skip AI calls."""

    def test_engine_works_with_ai_disabled(self, tmp_path):
        import os
        os.environ["DISABLE_AI_EXPLAINER"] = "true"
        try:
            from scanner.engine import ScanEngine
            target = tmp_path / "vuln.py"
            target.write_text("import os\ncmd = 'ls'\nos.system(cmd)\n")
            engine = ScanEngine(rules_dir=str(tmp_path))  # no rules dir → only AST/secret
            findings = engine.scan(str(tmp_path))
            # At minimum the AST analyzer should find the command injection
            assert any(f["id"] == "command_injection" for f in findings)
            # Every finding must have an ai_explanation key even when AI is disabled
            for f in findings:
                assert "ai_explanation" in f
        finally:
            del os.environ["DISABLE_AI_EXPLAINER"]
