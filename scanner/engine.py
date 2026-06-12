import os
import subprocess
import json
from typing import List, Dict, Any
from .ai_explainer import AIExplainer
from .ast_analyzer import ASTAnalyzer
from .secret_detector import SecretDetector

class ScanEngine:
    def __init__(self, rules_dir: str, ai_explainer: AIExplainer = None):
        self.rules_dir = rules_dir
        # Disable AI explainer if environment variable is set
        if os.getenv("DISABLE_AI_EXPLAINER") == "true":
            self.ai_explainer = None
        else:
            self.ai_explainer = ai_explainer or AIExplainer()
        self.ast_analyzer = ASTAnalyzer()
        self.secret_detector = SecretDetector()

    def run_semgrep(self, target_path: str) -> List[Dict[str, Any]]:
        # Run semgrep with the rules in rules_dir
        # we use --config to specify the directory of rules
        cmd = [
            "semgrep",
            "--config", self.rules_dir,
            "--json",
            target_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            findings = []

            for match in data.get("results", []):
                findings.append({
                    "id": match.get("check_id"),
                    "message": match.get("extra", {}).get("message"),
                    "file": match.get("path"),
                    "line": match.get("start", {}).get("line"),
                    "snippet": match.get("extra", {}).get("lines"),
                    "severity": match.get("extra", {}).get("severity", "ERROR")
                })
            return findings
        except Exception as e:
            print(f"Error running semgrep: {e}")
            return []

    def scan(self, target_path: str) -> List[Dict[str, Any]]:
        # 1. Semgrep findings
        findings = self.run_semgrep(target_path)

        # 2. AST-based findings for Python files
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()

                        # AST Analysis
                        ast_findings = self.ast_analyzer.analyze_file(file_path, content)
                        findings.extend(ast_findings)

                        # Secret Detection
                        secret_findings = self.secret_detector.analyze_file(file_path, content)
                        findings.extend(secret_findings)
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")

        # Augment findings with AI explanations (only when AI explainer is enabled)
        for finding in findings:
            if self.ai_explainer is not None:
                ai_data = self.ai_explainer.explain_finding(finding)
            else:
                ai_data = {
                    "explanation": "AI explanations disabled (DISABLE_AI_EXPLAINER=true).",
                    "remediation": "Consult the OWASP guidelines for remediation advice.",
                    "risk_level": "Unknown",
                }
            finding["ai_explanation"] = ai_data

        return findings
