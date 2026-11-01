# shx: AI-Assisted Terminal & Shell Command Assistant

`shx` is an AI-assisted command-line assistant built with Python, Typer, and Rich. It translates natural language into verified shell commands (Bash/Zsh), checks command safety before execution using AST parsing and heuristic guardrails (e.g. blocking fork bombs, recursive root wipe, accidental permission changes), and explains cryptic flags or command outputs.

---

## Key Features

1. **Natural Language to Shell Translation**:
   - Environment-aware command synthesis (adapts to macOS BSD vs Linux GNU tools, architecture, active shell, directory context, git status).
   - Fast multi-provider support: **Google Gemini**, **OpenAI**, **Groq**, and **Ollama / Local LLMs**.
2. **AST-Based Safety Guardrails (`bashlex`)**:
   - Parses the command into an Abstract Syntax Tree (AST) before execution.
   - Blocks **Critical** threats (e.g., `rm -rf /`, `rm -rf /*`, `:(){ :|:& };:`, raw disk writes like `dd of=/dev/sda`, `chmod -R 777 /var`).
   - Warns on **Dangerous** patterns (e.g., `curl ... | bash`, `git reset --hard`, `sudo`, `kill -9`).
3. **Cryptic Flags Explainer**:
   - High-speed offline knowledge base for notoriously cryptic Unix utilities: `tar`, `find`, `rsync`, `chmod`, `curl`, `awk`, `sed`, `grep`, `xargs`, `lsof`, `ps`.
   - AI-powered deep explainer for complex shell pipelines and terminal error messages.
4. **Interactive Rich Terminal UI**:
   - Color-coded risk badges (`SAFE`, `MODERATE RISK`, `DANGEROUS`, `CRITICAL - BLOCKED`).
   - Quick interactive menu: `[E]xecute`, `[C]opy to clipboard`, `[Ex]plain`, `[M]odify`, `[A]bort`.

---

## Installation

### Option 1: Global Install with `pipx` (Recommended)
[`pipx`](https://pypa.github.io/pipx/) installs CLI tools in isolated environments while making them globally accessible across your entire system:

```bash
# Install via PyPI
pipx install shx-cli

# Or install directly from GitHub
pipx install git+https://github.com/Fr0xy0p/Shx.git
```

### Option 2: Standard pip Install
```bash
pip install shx-cli

# Or directly from GitHub
pip install git+https://github.com/Fr0xy0p/Shx.git
```

### Option 3: Local Development
```bash
# Clone and navigate to workspace
git clone https://github.com/Fr0xy0p/Shx.git
cd Shx

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## Updating to the Latest Version

If you already have `shx` installed (e.g. `v0.1.0`) and want to update to the latest release:

```bash
# If installed via pipx:
pipx upgrade shx-cli
# Or if installed from GitHub via pipx:
pipx install --force git+https://github.com/Fr0xy0p/Shx.git

# If installed via standard pip:
pip install --upgrade shx-cli
# Or if installed from GitHub via pip:
pip install --upgrade git+https://github.com/Fr0xy0p/Shx.git

# If running from a local git clone:
git pull origin main
pip install -e .
```

Verify your installed version:
```bash
shx --version
```

### Troubleshooting: `shx: command not found`

If your terminal says `shx: command not found` after installing:
- **With `pipx`**: Run `pipx ensurepath` to add `~/.local/bin` to your shell's `$PATH`, then restart your terminal.
- **With `pip`**: Ensure Python's user bin directory (`~/.local/bin` or `~/Library/Python/3.x/bin`) is in your `$PATH`.
- **With a local venv**: Ensure your virtual environment is active (`source .venv/bin/activate`), or symlink the executable globally:
  ```bash
  ln -sf $(pwd)/.venv/bin/shx ~/.local/bin/shx
  ```

### Shell Integration (Directory Navigation & Environment Changes)

In Unix and macOS, an external command-line program runs as a child process and cannot alter the parent terminal's working directory (`cd`) or environment (`export`) directly. 

To enable seamless terminal navigation when running `shx "navigate into folder"`:
```bash
# One-click setup (adds integration to ~/.zshrc or ~/.bashrc)
shx setup

# Or manually add to ~/.zshrc:
eval "$(shx init zsh)"
```
Then run `source ~/.zshrc` (or restart your terminal). Now executing `cd` commands inside `shx` will navigate your terminal directly into that directory!

---

## Configuration

> [!IMPORTANT]
> **Bring Your Own API Key**: `shx` does not bundle private API keys. To generate commands using cloud providers, you must supply your own API key for **Google Gemini**, **Groq**, or **OpenAI**. 
>
> If you prefer not to use an API key, you can run `shx` completely free and offline by pointing it to **Ollama** with local models.

Set your preferred provider and API keys:

```bash
# Configure interactively (guided prompt)
shx config

# Or configure Groq directly
shx config --provider groq
shx config --set-key groq="gsk_your_groq_api_key_here"

# Or configure Google Gemini
shx config --provider gemini
shx config --set-key gemini="AIzaSy..."

# Alternatively, export standard environment variables
export GROQ_API_KEY="gsk_..."
export GEMINI_API_KEY="AIzaSy..."
export OPENAI_API_KEY="sk-..."

# Use local models via Ollama (no API key needed)
shx config --provider ollama
shx config --ollama-url "http://localhost:11434/v1"

# View current settings
shx config --show
```

---

## Usage

### 1. Translate Natural Language to Shell Commands
```bash
shx "find all files modified in the last 24 hours larger than 50MB"
shx "convert all png images to webp in this directory"
shx "show top 5 memory consuming processes"
```

### 2. Audit Safety with AST Guardrails
Audit any command to inspect risk scores, violations, and whether it would be blocked:
```bash
# Critical threat check (blocked)
shx check "rm -rf /"
shx check ":(){ :|:& };:"
shx check "dd if=/dev/urandom of=/dev/sda"

# Dangerous pattern check (warns)
shx check "curl -sSL https://get.docker.com | bash"
shx check "git reset --hard HEAD~1"

# Safe read-only check
shx check "ls -lh /var/log"
```

### 3. Explain Cryptic Flags & Commands
```bash
# Explain flags (tar, rsync, find, etc.)
shx explain "tar -xzvf archive.tar.gz -C /opt"
shx explain "rsync -avzP --delete src/ dest/"

# Explain last executed command
shx explain --last
```

### 4. System & Environment Info
```bash
shx info
```

---

## Running Tests

```bash
source .venv/bin/activate
pytest -v
```
