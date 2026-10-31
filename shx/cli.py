"""Command-line interface entrypoints for shx."""

import sys
from typing import Optional, List
import typer
from rich.prompt import Prompt
from rich.table import Table
from rich.markup import escape

import shx
from shx.core.config import (
    load_config,
    save_config,
    DEFAULT_CONFIG_PATH,
    SUPPORTED_PROVIDERS,
)
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
    context_settings={"help_option_names": ["-h", "--help"]},
)

guardrail = SafetyGuardrail()


def version_callback(value: bool):
    if value:
        console.print(f"shx version {shx.__version__}")
        raise typer.Exit()


def _handle_run_query(query: str):
    """Core translation, guardrail verification, and interactive execution flow."""
    config = load_config()
    client = LLMClient(config)
    context = get_system_context()

    try:
        with console.status(f"[bold cyan]Translating request via {config.default_provider}...[/bold cyan]", spinner="dots"):
            suggestion = client.translate(query, context)
    except KeyboardInterrupt:
        console.print("\n[dim]Aborted translation.[/dim]")
        sys.exit(130)
    except LLMError as e:
        console.print(f"\n[bold red]LLM Error:[/bold red] {escape(str(e))}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {escape(str(e))}")
        sys.exit(1)

    cmd = suggestion.command.strip()
    if not cmd:
        console.print("[bold red]Could not generate a command for the given request.[/bold red]")
        sys.exit(1)

    # Run AST and heuristic safety guardrails
    report = guardrail.evaluate(cmd)

    # Handle strict safety override: if disabled, CRITICAL is not hard-blocked
    if not config.strict_safety and report.level == RiskLevel.CRITICAL:
        report.is_blocked = False

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

    # If require_confirmation is False and command is SAFE, execute without prompt
    if not config.require_confirmation and report.level == RiskLevel.SAFE and not report.is_blocked:
        console.print(f"\n[dim]Auto-executing (require_confirmation=False):[/dim] [cyan]{escape(cmd)}[/cyan]\n")
        exit_code = execute_command_interactive(cmd)
        sys.exit(exit_code)

    # Interactive action loop
    while True:
        action = prompt_action(report)

        if action in ("e", "execute"):
            if report.is_blocked:
                console.print(
                    "[bold red]Action blocked. Execution is prevented by safety guardrails. "
                    "Use '[bold cyan]ex[/bold cyan]' to explain or '[bold cyan]a[/bold cyan]' to abort.[/bold red]"
                )
                continue

            if not config.strict_safety and report.level == RiskLevel.CRITICAL:
                typed = Prompt.ask("[bold red]This is a CRITICAL command. Type 'yes' to proceed with execution[/bold red]")
                if typed.strip().lower() != "yes":
                    console.print("[yellow]Execution cancelled.[/yellow]")
                    continue

            console.print(f"\n[dim]Running:[/dim] [cyan]{escape(cmd)}[/cyan]\n")
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
                console.print(f"[yellow]Could not fetch full AI explanation: {escape(str(e))}[/yellow]")
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
                if not config.strict_safety and report.level == RiskLevel.CRITICAL:
                    report.is_blocked = False
                local_flags = explain_local_command(cmd)
                flags = [FlagExplanation(flag=lf.flag, description=f"{lf.name}: {lf.description}") for lf in local_flags]
                render_command_card(cmd, "Modified command", report, flags)

        elif action in ("a", "q", "abort"):
            console.print("[dim]Aborted.[/dim]")
            sys.exit(0)
        else:
            console.print(f"[yellow]Unknown action '{escape(action)}'. Options: [E]xecute, [C]opy, [Ex]plain, [M]odify, [A]bort[/yellow]")


@app.callback(invoke_without_command=True)
def main_entry(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", "-v", callback=version_callback, is_eager=True, help="Show shx version and exit"
    ),
):
    """AI-Assisted Shell Command Assistant with AST Safety Guardrails."""
    if ctx.invoked_subcommand is None:
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


@app.command("explain", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def explain_command(
    target: Optional[List[str]] = typer.Argument(None, help="Shell command to explain (or leave blank with --last)"),
    last: bool = typer.Option(False, "--last", "-l", help="Explain the last command recorded in shx history"),
    error: bool = typer.Option(False, "--error", "-e", help="Explain error output instead of a command"),
):
    """Explain cryptic flags, shell syntax, or terminal error output."""
    cmd_to_explain = " ".join(target).strip() if target else None

    if last:
        cmd_to_explain = get_last_history_command()
        if not cmd_to_explain:
            console.print("[yellow]No previous command found in shx history.[/yellow]")
            raise typer.Exit(1)
        console.print(f"[dim]Explaining last recorded command:[/dim] [cyan]{escape(cmd_to_explain)}[/cyan]")

    if not cmd_to_explain:
        console.print("[bold red]Please provide a command to explain or use --last.[/bold red]")
        raise typer.Exit(1)

    config = load_config()
    client = LLMClient(config)

    # Offline flag check only when not analyzing error output
    local_flags = []
    if not error:
        local_flags = explain_local_command(cmd_to_explain)
        if local_flags:
            flag_table = Table(title="[bold blue]Cryptic Flags Identified (Local)[/bold blue]", border_style="blue")
            flag_table.add_column("Flag", style="bold green", width=15)
            flag_table.add_column("Name", style="cyan", width=22)
            flag_table.add_column("Meaning", style="white")
            for lf in local_flags:
                flag_table.add_row(escape(lf.flag), escape(lf.name), escape(lf.description))
            console.print(flag_table)

    # Call LLM for deep markdown explanation
    try:
        with console.status(f"[bold cyan]Querying {config.default_provider} for detailed breakdown...[/bold cyan]", spinner="dots"):
            explanation = client.explain(cmd_to_explain, is_error=error)
        render_markdown_explanation(explanation)
    except Exception as e:
        if local_flags:
            console.print(f"[dim yellow]Warning: AI explanation unavailable ({escape(str(e))})[/dim yellow]")
        else:
            console.print(f"[bold red]Error explaining target:[/bold red] {escape(str(e))}")
            raise typer.Exit(1)


@app.command("check", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def check_safety(
    command: List[str] = typer.Argument(..., help="Shell command to audit against safety guardrails"),
):
    """Audit a shell command against AST checks and destructive pattern guardrails."""
    target_cmd = " ".join(command).strip()
    report = guardrail.evaluate(target_cmd)
    render_safety_report(report)


@app.command("config")
def manage_config(
    show: bool = typer.Option(False, "--show", "-s", help="Display current configuration"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Set default LLM provider (gemini, openai, groq, ollama)"),
    set_key: Optional[str] = typer.Option(None, "--set-key", "-k", help="Set API key in format provider=KEY (e.g. gemini=AIza...)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Set default model for provider"),
    ollama_url: Optional[str] = typer.Option(None, "--ollama-url", help="Set base URL for Ollama / local LLM"),
    auto_copy: Optional[bool] = typer.Option(None, "--auto-copy/--no-auto-copy", help="Toggle automatic clipboard copying"),
    confirm: Optional[bool] = typer.Option(None, "--confirm/--no-confirm", help="Require confirmation before executing commands"),
    strict_safety: Optional[bool] = typer.Option(None, "--strict-safety/--no-strict-safety", help="Strict AST safety blocking critical threats"),
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
        table.add_row("Require Confirmation", str(cfg.require_confirmation))
        table.add_row("Strict Safety", str(cfg.strict_safety))
        table.add_row("Auto-copy Clipboard", str(cfg.auto_copy_clipboard))

        # Check API key status using single source of truth
        for p in SUPPORTED_PROVIDERS:
            has_key = bool(cfg.get_api_key(p))
            status_text = "[green]Configured[/green]" if has_key else "[dim]Not set[/dim]"
            table.add_row(f"API Key: {p}", status_text)

        console.print(table)
        return

    # Track if any command-line options were supplied
    has_options = any(
        opt is not None for opt in (provider, set_key, model, ollama_url, auto_copy, confirm, strict_safety)
    )

    if has_options:
        if provider:
            p_clean = provider.strip().lower()
            if p_clean in SUPPORTED_PROVIDERS:
                cfg.default_provider = p_clean
                console.print(f"[green]✔ Default provider set to: {p_clean}[/green]")
            else:
                supported_str = ", ".join(SUPPORTED_PROVIDERS)
                console.print(f"[red]Unsupported provider '{escape(provider)}'. Choose from: {supported_str}[/red]")
                raise typer.Exit(1)

        if set_key:
            if "=" in set_key:
                p, k = set_key.split("=", 1)
                p_clean = p.strip().lower()
                if p_clean not in SUPPORTED_PROVIDERS:
                    supported_str = ", ".join(SUPPORTED_PROVIDERS)
                    console.print(f"[red]Unsupported provider '{escape(p_clean)}'. Choose from: {supported_str}[/red]")
                    raise typer.Exit(1)
                cfg.api_keys[p_clean] = k.strip()
                console.print(f"[green]✔ Saved API key for {p_clean}[/green]")
            else:
                console.print("[red]Invalid format. Use --set-key provider=KEY[/red]")
                raise typer.Exit(1)

        if model:
            cfg.models[cfg.default_provider] = model.strip()
            console.print(f"[green]✔ Model for {cfg.default_provider} set to: {escape(model.strip())}[/green]")

        if ollama_url:
            cfg.ollama_base_url = ollama_url.strip()
            console.print(f"[green]✔ Ollama base URL set to: {escape(cfg.ollama_base_url)}[/green]")

        if auto_copy is not None:
            cfg.auto_copy_clipboard = auto_copy
            console.print(f"[green]✔ Auto-copy clipboard set to: {auto_copy}[/green]")

        if confirm is not None:
            cfg.require_confirmation = confirm
            console.print(f"[green]✔ Require confirmation set to: {confirm}[/green]")

        if strict_safety is not None:
            cfg.strict_safety = strict_safety
            console.print(f"[green]✔ Strict safety set to: {strict_safety}[/green]")

        save_config(cfg)
        return

    # Interactive wizard runs ONLY if no options were provided
    console.print("[bold cyan]shx Interactive Setup[/bold cyan]\n")
    new_provider = Prompt.ask(
        "Select default provider",
        choices=list(SUPPORTED_PROVIDERS),
        default=cfg.default_provider,
    )
    cfg.default_provider = new_provider

    if new_provider != "ollama":
        current_key = cfg.get_api_key(new_provider) or ""
        masked_prompt = f"Enter {new_provider.capitalize()} API Key"
        if current_key:
            masked_prompt += f" \\[leave blank to keep current: ...{current_key[-4:]}]"
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
        "-V",
        "-v",
    }
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands and not sys.argv[1].startswith("-"):
        sys.argv.insert(1, "run")
    app()


if __name__ == "__main__":
    main()
