import os
import shutil
import tempfile
from scanner.engine import ScanEngine


def test_adversarial_bypass():
    """
    Test suite designed to attempt bypassing the SAST and Secrets scanner.
    Each test case writes a single file to a fresh temporary directory so
    finding counts are never inflated by sibling test files.
    """
    test_cases = {
        "obfuscated_cmd": {
            "content": "import os\ncmd = 'ls'; os.system(cmd)",
            "expected": "command_injection",
        },
        "obfuscated_sql": {
            "content": (
                "import sqlite3\n"
                "conn = sqlite3.connect(':memory:')\n"
                "cursor = conn.cursor()\n"
                "query = 'SELECT * FROM users WHERE id = ' + '1'\n"
                "cursor.execute(query)"
            ),
            "expected": "sql_injection",
        },
        "entropy_bypass_attempt": {
            "content": "API_KEY = 'short_key'",
            "expected": None,  # Too short / low entropy — should not trigger
        },
        "high_entropy_generic": {
            "content": "MY_SECRET_TOKEN = 'aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q'",
            "expected": "high_entropy_secret",
        },
        "dynamic_format_bypass": {
            "content": "import os\nuser = 'admin'\nos.system('echo {}'.format(user))",
            "expected": "command_injection",
        },
    }

    engine = ScanEngine(rules_dir="rules")
    results = []

    for name, case in test_cases.items():
        # Fresh isolated directory for every test case
        test_dir = tempfile.mkdtemp(prefix=f"sast_adv_{name}_")
        try:
            file_path = os.path.join(test_dir, f"{name}.py")
            with open(file_path, "w") as fh:
                fh.write(case["content"])

            findings = engine.scan(test_dir)
            file_findings = [f for f in findings if f["file"].endswith(f"{name}.py")]

            if case["expected"] is None:
                passed = len(file_findings) == 0
            else:
                passed = any(f["id"] == case["expected"] for f in file_findings)

            results.append({"case": name, "passed": passed, "findings": len(file_findings)})
            print(f"Case {name}: {'PASSED' if passed else 'FAILED'} (Findings: {len(file_findings)})")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    return results


if __name__ == "__main__":
    print("Running Adversarial Tests...")
    test_results = test_adversarial_bypass()
    passed_count = sum(1 for r in test_results if r["passed"])
    success_rate = (passed_count / len(test_results)) * 100
    print(f"Overall Success Rate: {success_rate:.2f}%")
    if success_rate < 100:
        exit(1)
