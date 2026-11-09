#!/usr/bin/env bash
# install.sh — put `kestrel` on your PATH (symlink into ~/.local/bin). Re-run safely.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${KESTREL_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN"
chmod +x "$ROOT/kestrel" "$ROOT/lib/scope.py"
ln -sf "$ROOT/kestrel" "$BIN/kestrel"
echo "  ✓ kestrel → $BIN/kestrel"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "  ⚠ $BIN is not in \$PATH — add to your shell rc:  export PATH=\"$BIN:\$PATH\"" ;;
esac
echo "  › next: kestrel doctor"
