#!/usr/bin/env bash
# ============================================================
#  Claude Code Environment Installer
#  Stamps the global CLAUDE.md + memory system into any
#  OS user account so all Claude Code sessions benefit.
#
#  Sources implemented:
#    • Superpowers  (github.com/obra/superpowers)
#    • Caveman       (github.com/JuliusBrussee/caveman)
#    • Code Review   (claude.com/blog/code-review)
#    • Claude Mem    (Python SQLite edition — no Node.js needed)
#
#  Usage:
#    ./install_claude_config.sh           # installs for current user
#    sudo ./install_claude_config.sh bob  # installs for user 'bob'
# ============================================================

set -euo pipefail

TARGET_USER="${1:-$USER}"
if [[ "$TARGET_USER" != "$USER" ]]; then
    TARGET_HOME=$(eval echo "~$TARGET_USER")
else
    TARGET_HOME="$HOME"
fi

CLAUDE_DIR="$TARGET_HOME/.claude"
MEM_DIR="$CLAUDE_DIR/mem"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; AMBER='\033[0;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${AMBER}[warn]${NC}   $*"; }

echo ""
echo "  Claude Code Environment Installer"
echo "  ──────────────────────────────────"
echo "  Target user : $TARGET_USER"
echo "  Claude dir  : $CLAUDE_DIR"
echo ""

# ── Create directory structure ────────────────────────────────────────────
mkdir -p "$CLAUDE_DIR" "$MEM_DIR" "$MEM_DIR/sessions"
info "Directories created"

# ── Install global CLAUDE.md ──────────────────────────────────────────────
SOURCE_CLAUDE_MD="$HOME/.claude/CLAUDE.md"
TARGET_CLAUDE_MD="$CLAUDE_DIR/CLAUDE.md"

if [[ -f "$SOURCE_CLAUDE_MD" ]]; then
    if [[ "$TARGET_CLAUDE_MD" != "$SOURCE_CLAUDE_MD" ]]; then
        cp "$SOURCE_CLAUDE_MD" "$TARGET_CLAUDE_MD"
        info "CLAUDE.md installed → $TARGET_CLAUDE_MD"
    else
        info "CLAUDE.md already in place"
    fi
else
    warn "Source CLAUDE.md not found at $SOURCE_CLAUDE_MD"
    warn "Run this script from the OpenForensics directory after initial setup"
fi

# ── Install mem.py ────────────────────────────────────────────────────────
SOURCE_MEM="$HOME/.claude/mem/mem.py"
TARGET_MEM="$MEM_DIR/mem.py"

if [[ -f "$SOURCE_MEM" ]]; then
    if [[ "$TARGET_MEM" != "$SOURCE_MEM" ]]; then
        cp "$SOURCE_MEM" "$TARGET_MEM"
        info "mem.py installed → $TARGET_MEM"
    else
        info "mem.py already in place"
    fi
else
    warn "mem.py not found — skipping memory system"
fi

# ── Install / merge settings.json ────────────────────────────────────────
TARGET_SETTINGS="$CLAUDE_DIR/settings.json"
SETTINGS_CONTENT='{
  "extraKnownMarketplaces": {
    "claude-plugins-official": {
      "source": {
        "source": "github",
        "repo": "anthropics/claude-plugins-official"
      }
    }
  }
}'

if [[ ! -f "$TARGET_SETTINGS" ]]; then
    echo "$SETTINGS_CONTENT" > "$TARGET_SETTINGS"
    info "settings.json created"
else
    info "settings.json already exists — left unchanged"
fi

# ── Fix ownership if installing for another user ──────────────────────────
if [[ "$TARGET_USER" != "$USER" ]]; then
    chown -R "$TARGET_USER:$TARGET_USER" "$CLAUDE_DIR" 2>/dev/null || \
    chown -R "$TARGET_USER" "$CLAUDE_DIR" 2>/dev/null || \
    warn "Could not change ownership — run: sudo chown -R $TARGET_USER $CLAUDE_DIR"
fi

# ── Create shell alias for mem CLI ────────────────────────────────────────
PYTHON=$(command -v python3 || command -v python || echo "python3")
ALIAS_LINE="alias cmem='$PYTHON $MEM_DIR/mem.py'"
SHELL_RC=""

if [[ -f "$TARGET_HOME/.zshrc" ]]; then
    SHELL_RC="$TARGET_HOME/.zshrc"
elif [[ -f "$TARGET_HOME/.bashrc" ]]; then
    SHELL_RC="$TARGET_HOME/.bashrc"
elif [[ -f "$TARGET_HOME/.bash_profile" ]]; then
    SHELL_RC="$TARGET_HOME/.bash_profile"
fi

if [[ -n "$SHELL_RC" ]]; then
    if ! grep -q "alias cmem=" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# Claude Mem CLI" >> "$SHELL_RC"
        echo "$ALIAS_LINE" >> "$SHELL_RC"
        info "Added 'cmem' alias to $SHELL_RC"
        info "Run: source $SHELL_RC  (or open a new terminal)"
    else
        info "'cmem' alias already in $SHELL_RC"
    fi
fi

# ── Node.js / claude-mem check (optional) ────────────────────────────────
if command -v node &>/dev/null && command -v npx &>/dev/null; then
    NODE_VER=$(node --version)
    info "Node.js $NODE_VER found"
    read -rp "  Install official claude-mem (Node.js version)? [y/N] " ans
    if [[ "${ans,,}" == "y" ]]; then
        npx claude-mem install
        info "claude-mem installed"
    fi
else
    warn "Node.js not installed — using Python SQLite memory system (fully equivalent)"
    warn "To install Node.js: https://nodejs.org  or  brew install node"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "  ✓  Installation complete for: $TARGET_USER"
echo ""
echo "  What was installed:"
echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │ ~/.claude/CLAUDE.md      Global workflow + style config     │"
echo "  │ ~/.claude/mem/mem.py     Persistent memory CLI (SQLite)     │"
echo "  │ ~/.claude/settings.json  Claude Code settings               │"
echo "  │ cmem alias               Memory CLI shortcut in your shell  │"
echo "  └─────────────────────────────────────────────────────────────┘"
echo ""
echo "  Memory CLI usage:"
echo "    cmem save \"user prefers dark theme\" --type feedback"
echo "    cmem search \"theme preferences\""
echo "    cmem list"
echo "    cmem export > memory_backup.md"
echo ""
echo "  To install for another account:"
echo "    sudo ./install_claude_config.sh <username>"
echo ""
