import os
import subprocess
from scanner.engine import ScanEngine

def test_adversarial_bypass():
    """
    Test suite designed to attempt bypassing the SAST and Secrets scanner.
    """
    test_cases = {
        "obfuscated_cmd": {
            "content": "import os\ncmd = 'ls'; os.system(cmd)",
            "expected": "command_injection"
        },
        "obfuscated_sql": {
            "content": "import sqlite3\nconn = sqlite3.connect(':memory:')\ncursor = conn.cursor()\nquery = 'SELECT * FROM users WHERE id = ' + '1'\ncursor.execute(query)",
            "expected": "sql_injection"
        },
        "entropy_bypass_attempt": {
            "content": "API_KEY = 'short_key'",
            "expected": None # Should not trigger if too short or low entropy
        },
        "high_entropy_generic": {
            "content": "MY_SECRET_TOKEN = 'aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q'",
            "expected": "high_entropy_secret"
        },
        "dynamic_format_bypass": {
            "content": "import os\nuser = 'admin'\nos.system('echo {}'.format(user))",
            "expected": "command_injection"
        }
    }

    results = []
    engine = ScanEngine(rules_dir="rules")

    # Create a temporary directory for test files
    test_dir = "adversarial_tests"
    os.makedirs(test_dir, exist_ok=True)

    try:
        for name, case in test_cases.items():
            file_path = os.path.join(test_dir, f"{name}.py")
            with open(file_path, "w") as f:
                f.write(case["content"])

            findings = engine.scan(test_dir)

            # Filter findings for this specific file
            file_findings = [f for f in findings if f["file"].endswith(f"{name}.py")]

            passed = False
            if case["expected"] is None:
                passed = len(file_findings) == 0
            else:
                passed = any(f["id"] == case["expected"] for f in file_findings)

            results.append({
                "case": name,
                "passed": passed,
                "findings": len(file_findings)
            })
            print(f"Case {name}: {'PASSED' if passed else 'FAILED'} (Findings: {len(file_findings)})")

    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir)

    return results

if __name__ == "__main__":
    print("Running Adversarial Tests...")
    test_results = test_adversarial_bypass()
    success_rate = (sum(1 for r in test_results if r["passed"]) / len(test_results)) * 100
    print(f"Overall Success Rate: {success_rate:.2f}%")
    if success_rate <<  100:
        exit(1)
