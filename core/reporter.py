from rich.console import Console
from rich.table import Table
from .risk_engine import RiskEngine

console = Console()

def display_results(findings):
    table = Table(title="🛡️ Caelis Scan Report", show_lines=True)

    table.add_column("Vulnerability", style="white")
    table.add_column("Risk Level", justify="center")
    table.add_column("Description", style="white")

    for f in findings:
        color = RiskEngine.get_color(f.risk_level)
        table.add_row(
            f.name,
            f"[{color}]{f.risk_level}[/{color}]",
            f.description
        )

    console.print(table)
