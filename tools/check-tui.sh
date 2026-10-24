#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m py_compile "$ROOT/tools/imsisting_tui.py"
bash -n "$ROOT/imsisting.sh"
python3 - "$ROOT" <<'PY'
from pathlib import Path
import runpy, sys
root=Path(sys.argv[1])
ns=runpy.run_path(str(root/'tools/imsisting_tui.py'),run_name='tui_check')
s=(root/'imsisting.sh').read_text(encoding='utf-8')
start=s.index('IMSISTING_MODULE_TABLE=(')
end=s.index('\n)',start)
mods=ns['parse_table_text'](s[start:end])
assert len(mods) >= 50, len(mods)
assert len({(m.category, m.key) for m in mods}) == len(mods)
assert all((root/'modules'/f'{m.module_id}.sh').is_file() for m in mods)
assert next(m for m in mods if m.title=='Baseband Exploits').module_id=='54_baseband_exploit'
assert next(m for m in mods if m.title=='Baseband NV/EFS').module_id=='56_baseband_diag'
print(f"TUI metadata: PASS ({len(mods)} unique modules; every module file exists)")
PY
out=$(python3 "$ROOT/tools/imsisting_tui.py" --root "$ROOT" </dev/null 2>&1) && { echo 'expected non-TTY refusal'; exit 1; } || rc=$?
[[ ${rc:-0} -eq 2 ]]
grep -q 'needs an interactive terminal' <<<"$out"
echo "TUI terminal guard: PASS"
TERM=xterm-256color script -q -c "bash '$ROOT/imsisting.sh' --tui" /tmp/imsisting-tui-check.typescript <<'KEYS' >/dev/null
q
KEYS
python3 - /tmp/imsisting-tui-check.typescript <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text(errors='replace')
for token in ('FIELD OPERATIONS CONSOLE','MODULE INDEX','MODULE BRIEF','SEARCH'):
    assert token in text, f'missing dashboard element: {token}'
assert '\x1b[?1049h' in text, 'curses alternate screen not activated'
print('TUI pseudo-terminal render: PASS')
PY
help=$(bash "$ROOT/imsisting.sh" --help)
grep -q -- '--tui' <<<"$help"
echo "Launcher help: PASS"
