"""Command-line interface entrypoints for shx."""

import sys
from typing import Optional, List
import typer
from rich.prompt import Prompt
from rich.table import Table

from shx.core.config import load_config, save_config, DEFAULT_CONFIG_PATH
from shx.core.context import get_system_context
from shx.core.safety.guardrail import SafetyGuardrail
from shx.core.safety.rules import RiskLevel
from shx.core.explainer import explain_local_command
from shx.core.executor import (
    execute_command_interactive,
    copy_to_clipboard,
    get_last_history_command,
)
from shx.llm.client import LLMClient, LLMError, FlagExplanation
from shx.ui.console import (
    console,
    render_command_card,
    render_safety_report,
    render_markdown_explanation,
    prompt_action,
)

app = typer.Typer(
    name="shx",
    help="AI-Assisted Terminal & Shell Command Assistant with AST Safety Guardrails",
    add_completion=False,
)

guardrail = SafetyGuardrail()


def _handle_run_query(query: str):
    """Core translation, guardrail verification, and interactive execution flow."""
    config = load_config()
    client = LLMClient(config)
    context = get_system_context()

    try:
        with console.status(f"[bold cyan]Translating request via {config.default_provider}...[/bold cyan]", spinner="dots"):
            suggestion = client.translate(query, context)
    except LLMError as e:
        console.print(f"\n[bold red]LLM Error:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {e}")
        sys.exit(1)

    cmd = suggestion.command.strip()
    if not cmd:
        console.print("[bold red]Could not generate a command for the given request.[/bold red]")
        sys.exit(1)

    # Run AST and heuristic safety guardrails
    report = guardrail.evaluate(cmd)

    # Enrich flag explanations with local dictionary if needed
    flags = list(suggestion.flags_breakdown)
    if not flags:
        local_flags = explain_local_command(cmd)
        flags = [FlagExplanation(flag=lf.flag, description=f"{lf.name}: {lf.description}") for lf in local_flags]

    # Auto-copy to clipboard if configured
    if config.auto_copy_clipboard:
        copy_to_clipboard(cmd)

    # Render interactive card
    render_command_card(
        command=cmd,
        summary=suggestion.summary,
        report=report,
        flags_breakdown=flags,
        notes=suggestion.notes,
    )

    # Interactive action loop
    while True:
        action = prompt_action(report)

        if action in ("e", "execute"):
            if report.is_blocked:
                console.print("[bold red]Action blocked. This command cannot be executed directly.[/bold red]")
                continue
            console.print(f"\n[dim]Running:[/dim] [cyan]{cmd}[/cyan]\n")
            exit_code = execute_command_interactive(cmd)
            sys.exit(exit_code)

        elif action in ("c", "copy"):
            success = copy_to_clipboard(cmd)
            if success:
                console.print("[bold green]✔ Copied command to system clipboard![/bold green]")
            else:
                console.print("[yellow]Clipboard tool not found. You can copy the command manually.[/yellow]")
            break

        elif action in ("ex", "x", "explain"):
            try:
                with console.status("[bold cyan]Generating deep explanation...[/bold cyan]", spinner="dots"):
                    explanation = client.explain(cmd)
                render_markdown_explanation(explanation)
            except Exception as e:
                console.print(f"[yellow]Could not fetch full AI explanation: {e}[/yellow]")
                # Display local flag analysis as fallback
                local_flags = explain_local_command(cmd)
                if local_flags:
                    md_text = "### Offline Flag Breakdown\n"
                    for lf in local_flags:
                        md_text += f"- **`{lf.flag}`** ({lf.name}): {lf.description}\n"
                    render_markdown_explanation(md_text)

        elif action in ("m", "modify"):
            new_cmd = Prompt.ask("[bold cyan]Edit command[/bold cyan]", default=cmd)
            if new_cmd and new_cmd != cmd:
                cmd = new_cmd
                report = guardrail.evaluate(cmd)
                local_flags = explain_local_command(cmd)
                flags = [FlagExplanation(flag=lf.flag, description=f"{lf.name}: {lf.description}") for lf in local_flags]
                render_command_card(cmd, "Modified command", report, flags)

        elif action in ("a", "q", "abort"):
            console.print("[dim]Aborted.[/dim]")
            sys.exit(0)
        else:
            console.print(f"[yellow]Unknown action '{action}'. Options: [E]xecute, [C]opy, [Ex]plain, [M]odify, [A]bort[/yellow]")


@app.callback(invoke_without_command=True)
def main_entry(ctx: typer.Context):
    """AI-Assisted Shell Command Assistant with AST Safety Guardrails."""
    if ctx.invoked_subcommand is None:
        # Show banner and quick examples
        console.print()
        console.print("[bold cyan]shx[/bold cyan] — [italic]AI-Assisted Terminal & Shell Command Assistant[/italic]")
        console.print("[dim]AST parsing • Multi-provider LLMs • Destructive safety guardrails • Cryptic flag explainer[/dim]")
        console.print()
        console.print("[bold]Quick Examples:[/bold]")
        console.print("  [green]shx \"find files modified in last 24h over 50MB\"[/green]")
        console.print("  [green]shx \"compress all png files into an archive\"[/green]")
        console.print("  [green]shx explain \"tar -xzvf archive.tar.gz\"[/green]")
        console.print("  [green]shx check \"rm -rf /var/log/*\"[/green]")
        console.print("  [green]shx config[/green]")
        console.print()
        console.print("Run [cyan]shx --help[/cyan] to see all available commands.")
        console.print()


@app.command("run")
def run_command(
    query: List[str] = typer.Argument(..., help="Natural language instruction for the command to generate"),
):
    """Translate natural language into verified shell command and run interactively."""
    _handle_run_query(" ".join(query).strip())


@app.command("explain")
def explain_command(
    target: Optional[str] = typer.Argument(None, help="Shell command to explain (or leave blank with --last)"),
    last: bool = typer.Option(False, "--last", "-l", help="Explain the last command recorded in shx history"),
    error: bool = typer.Option(False, "--error", "-e", help="Explain error output instead of a command"),
):
    """Explain cryptic flags, shell syntax, or terminal error output."""
    cmd_to_explain = target

    if last:
        cmd_to_explain = get_last_history_command()
        if not cmd_to_explain:
            console.print("[yellow]No previous command found in shx history.[/yellow]")
            sys.exit(1)
        console.print(f"[dim]Explaining last recorded command:[/dim] [cyan]{cmd_to_explain}[/cyan]")

    if not cmd_to_explain:
        console.print("[bold red]Please provide a command to explain or use --last.[/bold red]")
        sys.exit(1)

    config = load_config()
    client = LLMClient(config)

    # Offline flag check first
    local_flags = explain_local_command(cmd_to_explain)
    if local_flags and not error:
        flag_table = Table(title="[bold blue]Cryptic Flags Identified (Local)[/bold blue]", border_style="blue")
        flag_table.add_column("Flag", style="bold green", width=15)
        flag_table.add_column("Name", style="cyan", width=22)
        flag_table.add_column("Meaning", style="white")
        for lf in local_flags:
            flag_table.add_row(lf.flag, lf.name, lf.description)
        console.print(flag_table)

    # Call LLM for deep markdown explanation
    try:
        with console.status(f"[bold cyan]Querying {config.default_provider} for detailed breakdown...[/bold cyan]", spinner="dots"):
            explanation = client.explain(cmd_to_explain, is_error=error)
        render_markdown_explanation(explanation)
    except LLMError as e:
        if not local_flags:
            console.print(f"[bold red]LLM error:[/bold red] {e}")
    except Exception as e:
        if not local_flags:
            console.print(f"[bold red]Error:[/bold red] {e}")


@app.command("check")
def check_safety(
    command: str = typer.Argument(..., help="Shell command to audit against safety guardrails"),
):
    """Audit a shell command against AST checks and destructive pattern guardrails."""
    report = guardrail.evaluate(command)
    render_safety_report(report)


@app.command("config")
def manage_config(
    show: bool = typer.Option(False, "--show", "-s", help="Display current configuration"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Set default LLM provider (gemini, openai, groq, ollama)"),
    set_key: Optional[str] = typer.Option(None, "--set-key", "-k", help="Set API key in format provider=KEY (e.g. gemini=AIza...)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Set default model for provider"),
    ollama_url: Optional[str] = typer.Option(None, "--ollama-url", help="Set base URL for Ollama / local LLM"),
):
    """View and update shx configuration (API keys, default provider, models)."""
    cfg = load_config()

    if show:
        table = Table(title="[bold cyan]shx Configuration[/bold cyan]", border_style="cyan")
        table.add_column("Setting", style="bold green")
        table.add_column("Value", style="white")
        table.add_row("Config File", str(DEFAULT_CONFIG_PATH))
        table.add_row("Default Provider", cfg.default_provider)
        table.add_row("Current Model", cfg.get_model())
        table.add_row("Ollama URL", cfg.ollama_base_url)
        table.add_row("Auto-copy Clipboard", str(cfg.auto_copy_clipboard))
        table.add_row("Strict Safety", str(cfg.strict_safety))

        # Check API key status
        for p in ("gemini", "openai", "groq", "anthropic"):
            has_key = bool(cfg.get_api_key(p))
            status_text = "[green]Configured[/green]" if has_key else "[dim]Not set[/dim]"
            table.add_row(f"API Key: {p}", status_text)

        console.print(table)
        return

    updated = False
    if provider:
        p_clean = provider.strip().lower()
        if p_clean in ("gemini", "openai", "groq", "ollama", "anthropic"):
            cfg.default_provider = p_clean
            updated = True
            console.print(f"[green]✔ Default provider set to: {p_clean}[/green]")
        else:
            console.print(f"[red]Unsupported provider '{provider}'. Choose: gemini, openai, groq, ollama[/red]")

    if set_key:
        if "=" in set_key:
            p, k = set_key.split("=", 1)
            cfg.api_keys[p.strip().lower()] = k.strip()
            updated = True
            console.print(f"[green]✔ Saved API key for {p.strip().lower()}[/green]")
        else:
            console.print("[red]Invalid format. Use --set-key provider=KEY[/red]")

    if model:
        cfg.models[cfg.default_provider] = model.strip()
        updated = True
        console.print(f"[green]✔ Model for {cfg.default_provider} set to: {model.strip()}[/green]")

    if ollama_url:
        cfg.ollama_base_url = ollama_url.strip()
        updated = True
        console.print(f"[green]✔ Ollama base URL set to: {cfg.ollama_base_url}[/green]")

    if updated:
        save_config(cfg)
        return

    # Interactive wizard if no arguments were provided
    console.print("[bold cyan]shx Interactive Setup[/bold cyan]\n")
    new_provider = Prompt.ask(
        "Select default provider",
        choices=["gemini", "openai", "groq", "ollama"],
        default=cfg.default_provider,
    )
    cfg.default_provider = new_provider

    if new_provider != "ollama":
        current_key = cfg.get_api_key(new_provider) or ""
        masked_prompt = f"Enter {new_provider.capitalize()} API Key"
        if current_key:
            masked_prompt += f" [leave blank to keep current: ...{current_key[-4:]}]"
        entered_key = Prompt.ask(masked_prompt, default="", password=True)
        if entered_key:
            cfg.api_keys[new_provider] = entered_key
    else:
        new_url = Prompt.ask("Ollama Base URL", default=cfg.ollama_base_url)
        cfg.ollama_base_url = new_url

    save_config(cfg)
    console.print("\n[bold green]✔ Configuration saved successfully![/bold green]")


@app.command("info")
def system_info():
    """Display system environment, shell details, and shx status."""
    ctx = get_system_context()
    cfg = load_config()

    table = Table(title="[bold cyan]shx Environment & System Context[/bold cyan]", border_style="cyan")
    table.add_column("Property", style="bold green", width=22)
    table.add_column("Detected Value", style="white")

    table.add_row("Operating System", f"{ctx['os']} ({ctx['platform']})")
    table.add_row("Architecture", ctx["arch"])
    table.add_row("Current Shell", ctx["shell"])
    table.add_row("Working Directory", ctx["cwd"])
    table.add_row("Git Repository", "Yes" if ctx["git"]["is_git"] else "No")
    table.add_row("Active LLM Provider", cfg.default_provider)
    table.add_row("Active Model", cfg.get_model())

    console.print(table)


def main():
    """Main CLI entry point for console_scripts."""
    known_commands = {
        "run",
        "explain",
        "check",
        "config",
        "info",
        "--help",
        "-h",
        "--version",
        "-v",
    }
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands and not sys.argv[1].startswith("-"):
        sys.argv.insert(1, "run")
    app()


if __name__ == "__main__":
    main()
