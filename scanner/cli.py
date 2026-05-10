import argparse
import sys
import os
from rich.console import Console
from rich.table import Table
from .engine import ScanEngine
from .sarif_exporter import SarifExporter

def main():
    parser = argparse.ArgumentParser(description="AI-Augmented SAST Scanner")
    parser.add_argument("action", choices=["scan"], help="Action to perform")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--output", help="Path to save SARIF output", default="results.sarif")
    parser.add_argument("--rules", help="Path to rules directory", default="rules")

    args = parser.parse_args()
    console = Console()

    if args.action == "scan":
        # Use absolute path for rules if provided relatively
        rules_path = os.path.abspath(args.rules)

        console.print(f"[bold blue]Scanning {args.target} using rules from {rules_path}...[/bold blue]")

        engine = ScanEngine(rules_dir=rules_path)
        findings = engine.scan(args.target)

        if not findings:
            console.print("[green]No vulnerabilities found![/green]")
            return

        table = Table(title="Security Findings")
        table.add_column("ID", style="cyan")
        table.add_column("File", style="magenta")
        table.add_column("Line", style="yellow")
        table.add_column("Message", style="white")
        table.add_column("Risk", style="red")

        for f in findings:
            risk = f.get("ai_explanation", {}).get("risk_level", "Unknown")
            table.add_row(f["id"], f["file"], str(f["line"]), f["message"], risk)

        console.print(table)

        exporter = SarifExporter()
        exporter.export(findings, args.output)
        console.print(f"\n[bold green]SARIF report saved to {args.output}[/bold green]")

if __name__ == "__main__":
    main()
