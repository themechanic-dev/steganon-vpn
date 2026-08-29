#!/usr/bin/env python3
"""Checks that every PowerShell script carries a UTF-8 byte order mark.

Without one, Windows PowerShell 5.1 reads the file as ANSI: every non-Latin
character is mangled and the script fails with a syntax error that points
nowhere near the real cause. The check is cheap and the bug is expensive, so
it runs automatically.
"""

import sys
from pathlib import Path

BOM = b"\xef\xbb\xbf"
root = Path(__file__).resolve().parent.parent

missing = [p for p in root.rglob("*.ps1") if not p.read_bytes().startswith(BOM)]
for path in missing:
    print(f"missing UTF-8 byte order mark: {path.relative_to(root)}", file=sys.stderr)

if missing:
    print(f"\n{len(missing)} files will break under Windows PowerShell.", file=sys.stderr)
    sys.exit(1)

print(f"✓ {len(list(root.rglob('*.ps1')))} PowerShell scripts correctly marked")
