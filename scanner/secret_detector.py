import math
import re
from typing import List, Dict, Any

class SecretDetector:
    """
    Detects high-entropy strings that may be secrets (API keys, tokens, passwords).
    """
    def __init__(self, entropy_threshold: float = 3.8, min_length: int = 8):
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        # Common patterns for secrets to reduce false positives or specifically target
        self.secret_patterns = {
            "Generic API Key": r'(?i)(api_key|apikey|secret|token|passwd|password|auth_token)[\s:=]+["\']([a-zA-Z0-9_\-\.\~\/\+\=\+\/]{8,})["\']',
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Access Key": r'(?i)aws_secret_access_key[\s:=]+["\']([a-zA-Z0-9\/+]{40})["\']',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "GitHub Token": r'ghp_[a-zA-Z0-9]{36}',
            "Slack Token": r'xox[bapr]-[0-9a-zA-Z]{10,48}',
        }

    def calculate_entropy(self, s: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not s:
            return 0.0
        # Remove common characters that don't contribute to "secret-ness" in some contexts
        # but for general entropy, we keep them.
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy

    def analyze_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        Analyzes a file for secrets using both regex patterns and entropy analysis.
        """
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # 1. Pattern-based detection
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Use the captured group if available, otherwise the whole match
                    secret_value = match.group(2) if match.groups() and len(match.groups()) >= 2 else match.group(0)
                    findings.append({
                        "id": "secret_detected",
                        "message": f"Potential {secret_type} detected",
                        "file": file_path,
                        "line": line_num,
                        "snippet": line.strip(),
                        "severity": "ERROR",
                        "type": secret_type
                    })

            # 2. High-entropy detection (for generic secrets not caught by regex)
            # We look for strings that look like assignments: key = "value"
            # Improved regex to capture more assignment styles
            assignment_matches = re.finditer(r'(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\~\/\+\=\+\/]{8,})["\'])', line)
            for match in assignment_matches:
                var_name = match.group(1)
                value = match.group(2)

                # Only check entropy if it's not already caught by patterns
                # and the variable name suggests it's a secret
                if any(keyword in var_name.lower() for keyword in ["key", "secret", "token", "pass", "auth", "credential", "api"]):
                    entropy = self.calculate_entropy(value)
                    if entropy >= self.entropy_threshold:
                        # Avoid duplicating if not already caught by patterns on this line
                        if not any(f["line"] == line_num and f["snippet"] == line.strip() for f in findings):
                            findings.append({
                                "id": "high_entropy_secret",
                                "message": f"High entropy string ({entropy:.2f}) assigned to {var_name} may be a secret",
                                "file": file_path,
                                "line": line_num,
                                "snippet": line.strip(),
                                "severity": "ERROR",
                                "type": "High Entropy Secret"
                            })

        return findings
