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
# A key is a menu position, so it is unique across the whole table: two rows
# sharing one number make the second row unreachable by key (fn_for_key returns
# the first match) and leave a gap in the TUI's numbering column.
assert len({m.key for m in mods}) == len(mods), 'duplicate menu keys'
assert [m.key for m in mods] == [f'{i:02d}' for i in range(1, len(mods) + 1)], 'keys are not 01..N in table order'
assert all((root/'modules'/f'{m.module_id}.sh').is_file() for m in mods)
assert next(m for m in mods if m.title=='Baseband Exploits').module_id=='54_baseband_exploit'
assert next(m for m in mods if m.title=='Baseband NV/EFS').module_id=='56_baseband_diag'
# A row that points at the wrong script opens a page belonging to another
# module, which is invisible until somebody presses Enter on it.
for title, module_id in (('Remote Nodes', '59_remote_node'),
                         ('LTE Evil Twin', '57_evil_twin'),
                         ('Overshadowing / AdaptOver', '60_overshadow'),
                         ('5G SUCI Catcher', '58_suci_catcher')):
    hit = next(m for m in mods if m.title == title)
    assert hit.module_id == module_id, f'{title} opens {hit.module_id}'
full = ns['parse_modules'](root)
# An action list is a list of things to run, so it must not offer a verb that
# only exists as somebody's argument, and it must not be empty.
for module in full:
    groups = ns['grouped_actions'](module)
    offered = [v for _, verbs in groups for v in verbs]
    assert offered, f'{module.module_id} offers no action'
    bad = sorted(set(v for v in offered if v[2:] in ns['MODIFIERS']))
    assert not bad, f'{module.module_id} offers modifiers as actions: {bad}'
# The five newest modules came through the view system, not the flat fallback.
for module_id, least in (('59_remote_node', 3), ('57_evil_twin', 4),
                         ('60_overshadow', 5), ('58_suci_catcher', 4)):
    module = next(m for m in full if m.module_id == module_id)
    named = [t for t, _ in ns['grouped_actions'](module) if t != 'Other actions']
    assert len(named) >= least, f'{module_id} has only {named}'
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
for token in ('IMSISTING', 'CATEGORIES', 'MODULES', 'SEARCH'):
    assert token in text, f'missing dashboard element: {token}'
assert '\x1b[?1049h' in text, 'curses alternate screen not activated'
print('TUI pseudo-terminal render: PASS')
PY
help=$(bash "$ROOT/imsisting.sh" --help)
grep -q -- '--tui' <<<"$help"
echo "Launcher help: PASS"
