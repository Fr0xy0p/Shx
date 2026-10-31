"""Rich terminal UI formatting, badges, panels, and interactive menus."""

from typing import List, Optional
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown

from shx.core.safety.rules import RiskLevel, RiskReport
from shx.llm.client import FlagExplanation

console = Console()


def get_risk_badge(level: RiskLevel, score: int) -> Text:
    """Generate color-coded risk badge."""
    if level == RiskLevel.SAFE:
        return Text(f" SAFE ({score}/100) ", style="bold green on #1c2e1c")
    elif level == RiskLevel.MODERATE:
        return Text(f" MODERATE RISK ({score}/100) ", style="bold yellow on #332b00")
    elif level == RiskLevel.DANGEROUS:
        return Text(f" DANGEROUS ({score}/100) ", style="bold white on #8b0000")
    elif level == RiskLevel.CRITICAL:
        return Text(f" CRITICAL - BLOCKED ({score}/100) ", style="bold white on red")
    return Text(f" UNKNOWN ({score}/100) ")


def render_command_card(
    command: str,
    summary: str,
    report: RiskReport,
    flags_breakdown: Optional[List[FlagExplanation]] = None,
    notes: Optional[str] = None,
) -> None:
    """Render full command card with syntax highlighting and safety breakdown."""
    console.print()

    # Header with Summary & Risk Badge
    badge = get_risk_badge(report.level, report.score)
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left")
    header_table.add_column(justify="right")
    header_table.add_row(Text(summary or "Synthesized command", style="bold cyan"), badge)

    console.print(header_table)
    console.print()

    # Syntax highlighted command
    syntax = Syntax(command, "bash", theme="monokai", line_numbers=False, word_wrap=True)
    border_color = "red" if report.level in (RiskLevel.CRITICAL, RiskLevel.DANGEROUS) else "cyan" if report.level == RiskLevel.SAFE else "yellow"
    console.print(Panel(syntax, title="[bold]Command[/]", border_style=border_color, expand=True))

    # Safety Violations Warning Box
    if report.violations:
        console.print()
        violation_table = Table(title="[bold red]Safety Guardrail Analysis[/]", border_style="red", expand=True)
        violation_table.add_column("Severity", justify="center", style="bold", width=12)
        violation_table.add_column("Rule", style="cyan", width=22)
        violation_table.add_column("Details", style="white")

        for v in report.violations:
            sev_color = "red" if v.severity in (RiskLevel.CRITICAL, RiskLevel.DANGEROUS) else "yellow"
            violation_table.add_row(
                f"[{sev_color}]{v.severity.value}[/{sev_color}]",
                escape(v.rule_id),
                f"{escape(v.message)}\n[dim italic]{escape(v.rationale)}[/dim italic]",
            )
        console.print(violation_table)

    # Flag breakdown table
    if flags_breakdown:
        console.print()
        flag_table = Table(title="[bold blue]Flag & Parameter Breakdown[/]", border_style="blue", expand=True)
        flag_table.add_column("Flag / Token", style="bold green", width=20)
        flag_table.add_column("Function", style="white")
        for f in flags_breakdown:
            flag_table.add_row(escape(f.flag), escape(f.description))
        console.print(flag_table)

    # Notes or safety tip
    if notes:
        console.print()
        console.print(f"[dim]Tip: {escape(notes)}[/dim]")

    console.print()


def render_safety_report(report: RiskReport) -> None:
    """Render audit report for `shx check` command with escaped markup."""
    console.print()
    badge = get_risk_badge(report.level, report.score)

    console.print(f"[bold]Target Command:[/bold] [italic cyan]{escape(report.command)}[/italic cyan]")
    console.print("[bold]Risk Assessment:[/bold] ", end="")
    console.print(badge)
    console.print(f"[bold]AST Parsed Successfully:[/bold] {'[green]Yes[/green]' if report.ast_parsed else '[yellow]No (Fallback Shlex Used)[/yellow]'}")
    console.print(f"[bold]Execution Status:[/bold] {'[red]BLOCKED[/red]' if report.is_blocked else '[green]ALLOWED[/green]'}")

    if report.violations:
        console.print()
        table = Table(title="[bold]Detected Violations & Risky Patterns[/]", border_style="red", expand=True)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", style="cyan", width=24)
        table.add_column("Description", style="white")

        for v in report.violations:
            sev_color = "red" if v.severity in (RiskLevel.CRITICAL, RiskLevel.DANGEROUS) else "yellow"
            table.add_row(
                f"[{sev_color}]{v.severity.value}[/{sev_color}]",
                escape(v.rule_id),
                f"{escape(v.message)}\n[dim]{escape(v.rationale)}[/dim]",
            )
        console.print(table)
    else:
        console.print("\n[green]No dangerous patterns detected. Command is safe to execute.[/green]")
    console.print()


def render_markdown_explanation(markdown_text: str) -> None:
    """Render rich markdown explanation panel."""
    console.print()
    md = Markdown(markdown_text)
    console.print(Panel(md, title="[bold cyan]Command & Flags Explanation[/bold cyan]", border_style="cyan", expand=True))
    console.print()


def prompt_action(report: RiskReport) -> str:
    """Display interactive action prompt with safe default behavior and unambiguous hotkeys."""
    if report.is_blocked:
        console.print("[bold red]This command is BLOCKED by safety guardrails due to critical risks.[/bold red]")
        prompt_text = "[bold][C]opy to clipboard | [Ex]plain | [A]bort[/bold] (default: Abort): "
        allowed = {"c", "copy", "ex", "explain", "x", "a", "abort", "q", ""}
        default_action = "a"
    elif report.level == RiskLevel.DANGEROUS:
        console.print("[bold yellow]WARNING: High-risk command detected. Please verify before running.[/bold yellow]")
        prompt_text = "[bold][E]xecute | [C]opy | [Ex]plain | [M]odify | [A]bort[/bold] (default: Abort): "
        allowed = {"e", "execute", "c", "copy", "ex", "explain", "x", "m", "modify", "a", "abort", "q", ""}
        default_action = "a"
    else:
        prompt_text = "[bold][E]xecute | [C]opy | [Ex]plain | [M]odify | [A]bort[/bold] (default: Execute): "
        allowed = {"e", "execute", "c", "copy", "ex", "explain", "x", "m", "modify", "a", "abort", "q", ""}
        default_action = "e"

    try:
        user_input = console.input(prompt_text).strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Aborted.[/dim]")
        return "a"

    if not user_input:
        return default_action

    if user_input not in allowed:
        return user_input

    return user_input
