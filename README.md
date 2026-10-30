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
pipx install git+https://github.com/<your-username>/shx.git
```

### Option 2: Standard pip Install
```bash
pip install shx-cli
```

### Option 3: Local Development
```bash
# Clone and navigate to workspace
git clone https://github.com/<your-username>/shx.git
cd shx

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## Configuration

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
