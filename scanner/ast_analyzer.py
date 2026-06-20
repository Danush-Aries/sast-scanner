import ast
from typing import List, Dict, Any

class ASTAnalyzer:
    """
    Analyzes Python AST for patterns indicating SQL Injection and Command Injection.
    """
    def __init__(self):
        # Sinks for Command Injection
        self.cmd_sinks = {
            'os.system',
            'os.popen',
            'subprocess.run',
            'subprocess.Popen',
            'subprocess.call',
            'subprocess.check_output',
            'subprocess.check_call',
            'platform.popen'
        }

        # Sinks for SQL Injection
        self.sql_sinks = {
            'execute',
            'executemany'
        }

    def _get_full_name(self, node: ast.AST) -> str:
        """Helper to resolve the full name of a function call (e.g., os.system)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_full_name(node.value)
            if value:
                return f"{value}.{node.attr}"
        return ""

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """
        Checks if a node represents a dynamic string (f-string, .format(), or % operator).
        Now includes basic constant folding detection for literals.
        """
        if isinstance(node, ast.JoinedStr):  # f-strings
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):  # "..." % var
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # "..." + var
            # Flag only when at least one operand is user-influenced
            # (a variable or call), not "a" + "b" of two literals.
            return (
                self._is_dynamic_string(node.left)
                or self._is_dynamic_string(node.right)
                or isinstance(node.left, (ast.Name, ast.Call))
                or isinstance(node.right, (ast.Name, ast.Call))
            )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return True
        if isinstance(node, ast.Name) and node.id == 'True': # Handle cases where True/False might be passed
            return False
        return False

    def analyze_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        Parses the Python code and looks for vulnerable patterns in the AST.
        """
        findings = []
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            return []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_full_name(node.func)

                # 1. Command Injection Detection
                if func_name in self.cmd_sinks:
                    if node.args:
                        arg = node.args[0]
                        # If the first argument is a dynamic string or a variable (not a constant)
                        if self._is_dynamic_string(arg) or (isinstance(arg, ast.Name)):
                            findings.append({
                                "id": "command_injection",
                                "message": f"Potential Command Injection: dynamic or variable argument passed to {func_name}",
                                "file": file_path,
                                "line": node.lineno,
                                "snippet": f"Call to {func_name} with potential dynamic argument",
                                "severity": "ERROR"
                            })

                # 2. SQL Injection Detection
                if any(sink in func_name for sink in self.sql_sinks):
                    if node.args:
                        arg = node.args[0]
                        if self._is_dynamic_string(arg) or (isinstance(arg, ast.Name)):
                            findings.append({
                                "id": "sql_injection",
                                "message": f"Potential SQL Injection: dynamic or variable argument passed to {func_name}",
                                "file": file_path,
                                "line": node.lineno,
                                "snippet": f"Call to {func_name} with potential dynamic argument",
                                "severity": "ERROR"
                            })

        return findings
