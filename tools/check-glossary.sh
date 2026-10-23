#!/usr/bin/env bash
# check-glossary.sh — fail if the interface promises vocabulary it cannot keep.
#
# The kit is read by two people at once: an engineer who knows what an RSRP is,
# and someone who has never opened a cellular specification. The interface is
# allowed to serve both, but only if every key it prints has been given words a
# beginner can read, and only if those words were decided rather than invented
# at the call site.
#
# So this check holds four promises:
#
#   1. every key the modules actually print has a plain-words row in the
#      dictionary (a key that reaches the screen without a row is a label the
#      beginner will not understand);
#   2. no dictionary row is dead weight — a row nobody can reach, or one that
#      misspells the key it means to cover, hides the key it was written for;
#   3. no view name and no button label contains a verb token (defence in depth
#      for check-gui-text.sh, which sees the rendering calls but not the label
#      a page carries in its own table);
#   4. every Goals route step names a verb its module actually documents — a
#      route that points at nothing is a broken promise, not a broken button.
#
# Usage: tools/check-glossary.sh [--json] [--list]
#   --list  show every rendered key, every label checked, every Goals step
# Exit: 0 if every promise holds, 1 if one is broken,
#       2 if this check cannot run at all (its inputs are missing).
#
# What it cannot see: a key that reaches a label through a variable, and a
# plain-words row whose wording is accurate but unhelpfully terse. The first
# would need the program run; the second is a person reading the dictionary.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/src/main1.c"
INDEX="$ROOT/native/src/module_index.c"
MODDIR="$ROOT/modules"

jsonout=0
listall=0
for a in "$@"; do
    case "$a" in
        --json) jsonout=1 ;;
        --list) listall=1 ;;
    esac
done

[[ -f "$SRC" ]]   || { echo "no $SRC" >&2; exit 2; }
[[ -f "$INDEX" ]] || { echo "no $INDEX" >&2; exit 2; }
[[ -d "$MODDIR" ]] || { echo "no $MODDIR" >&2; exit 2; }

exec python3 - "$SRC" "$INDEX" "$MODDIR" "$jsonout" "$listall" <<'PY'
import io, json, os, re, sys

src_path, index_path, moddir, jsonout, listall = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == '1', sys.argv[5] == '1')

def read(p):
    with io.open(p, encoding='utf-8', errors='replace') as f:
        return f.read()

main = read(src_path)
index = read(index_path)

problems = []
def bad(kind, detail):
    problems.append((kind, detail))

# ── the dictionary ──────────────────────────────────────────────────────────
m = re.search(r'static const char \*const plain_keys\[\] = \{(.*?)\n\};', main, re.S)
if not m:
    print('cannot find plain_keys[] in %s' % src_path, file=sys.stderr)
    sys.exit(2)
dict_rows = {}
for line in m.group(1).splitlines():
    mm = re.match(r'^\s*"([^"\\]+)\\t(.*)",\s*$', line)
    if not mm:
        continue
    dict_rows[mm.group(1)] = mm.group(2)
if not dict_rows:
    print('plain_keys[] is empty in %s' % src_path, file=sys.stderr)
    sys.exit(2)

# ── the keys the tree actually renders ──────────────────────────────────────
# A module prints an answer row as a printf whose first field is the key. The
# key is therefore the first tab-separated token of any printf format string.
KEY_RE = re.compile(r'^[a-z][a-z0-9_]*$')
HEX_RE = re.compile(r'^[0-9a-f]{24,}$')
harvest = set()
PRINTF_RE = re.compile(r"printf[ \t]+('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")")
PYSTR_RE = re.compile(r"(['\"])(.*?)\1", re.S)

def take(field):
    field = field.strip()
    if len(field) < 2 or HEX_RE.match(field):
        return
    if KEY_RE.match(field):
        harvest.add(field)

files = []
for base in (moddir, os.path.join(os.path.dirname(index_path), '..', '..', 'lib'),
             os.path.join(os.path.dirname(index_path), '..', '..', 'tools')):
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
        for name in sorted(filenames):
            if name.endswith(('.sh', '.inc', '.py')):
                files.append(os.path.join(dirpath, name))
for path in files:
    try:
        body = read(path)
    except OSError:
        continue
    if path.endswith('.py'):
        # a python tool writes the same key<TAB>value rows the shell modules
        # do, so its string literals are harvested the same way
        for mm in PYSTR_RE.finditer(body):
            lit = mm.group(2)
            if '\\t' not in lit and '\t' not in lit:
                continue
            for field in lit.replace('\\t', '\t').split('\t')[:1]:
                take(field)
        continue
    for mm in PRINTF_RE.finditer(body):
        # a printf that is captured by $( ... ) or redirected into a file is
        # building a fixture, not printing an answer row: its first field is a
        # coordinate, a filename or a chain step, and never reaches the screen
        line_start = body.rfind('\n', 0, mm.start()) + 1
        if re.search(r'\$\(\s*$', body[line_start:mm.start()]):
            continue
        line_end = body.find('\n', mm.end())
        if re.match(r'\s*>>?', body[mm.end():line_end if line_end >= 0 else len(body)]):
            continue
        fmt = mm.group(1)[1:-1]
        fmt = fmt.replace('%%', '\x00')
        fmt = fmt.replace('\\t', '\t').replace('\\n', '\t')
        for field in fmt.split('\t'):
            take(field)
if not harvest:
    print('no printf answer keys found under %s' % moddir, file=sys.stderr)
    sys.exit(2)

# ── keys the operator mandated by name ──────────────────────────────────────
# The brief that asked for this dictionary named thirty terms whether or not a
# module prints them standalone (many are emitted as compounds such as
# rsrp_dbm). They are kept as rows on purpose, so a bare label would still read
# in plain words if one appears; they are listed here so the "never used" check
# stays honest about which rows are mandate rather than harvest.
MANDATED = set('''
rsrp rsrq snr sinr rssi psc ecgi enb_id gnb_id smf upf imeisv supi mcc_mnc qci
five_qi nssai dnn ck kasme uia eea eia t3412 t3410 drx paging_tmsi freq chips
'''.split())

# ── promise 1: every rendered key has words ────────────────────────────────
missing = sorted(harvest - set(dict_rows))
if missing:
    bad('key-without-words', '%d rendered key(s) have no plain-words row: %s'
        % (len(missing), ', '.join(missing[:12])))

# ── promise 2: no dictionary row is dead weight ────────────────────────────
dead = sorted(set(dict_rows) - harvest - MANDATED)
if dead:
    bad('unused-row', '%d dictionary row(s) cover no key this tree prints: %s'
        % (len(dead), ', '.join(dead[:12])))

# ── promise 3: no label carries a verb token ───────────────────────────────
VERB = re.compile(r'(^|\s)--[a-zA-Z0-9]')
labels = []

# view names, from the _entries[] tables only (a page's own navigation names)
for entry in re.finditer(r'static ModuleSubmenuEntry \*\w+_entries\[\] = \{(.*?)\n\};', main, re.S):
    for row in re.finditer(r'^\s*\{\s*"([^"]+)"', entry.group(1), re.M):
        labels.append(('view', row.group(1)))

# button labels and the other rendered captions that carry a page name
for name in ('gtk_button_new_with_label', 'gtk_toggle_button_new_with_label',
             'gtk_check_button_new_with_label', 'verb_card', 'radio_view_shell'):
    for mm in re.finditer(r'\b' + name + r'\(\s*"((?:[^"\\]|\\.)*)"', main):
        labels.append((name, mm.group(1).encode().decode('unicode_escape')))

if not labels:
    print('no view names or button labels found in %s' % src_path, file=sys.stderr)
    sys.exit(2)

for kind, text in labels:
    if VERB.search(text) or text.startswith('--'):
        bad('verb-in-label', '%s label "%s" is named after a verb' % (kind, text))

# ── promise 4: every Goals step names a documented verb ────────────────────
modules = {}
for row in re.finditer(r'\{\s*"([^"]+)"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*"([^"]*)"',
                       index):
    modules[row.group(1)] = set(row.group(2).split())
if not modules:
    print('no module rows found in %s' % index_path, file=sys.stderr)
    sys.exit(2)

# plumbing verbs a module documents only in its own dispatcher
EXEMPT = set('--menu --selftest --status-tsv --info --__index_probe__ --yes '
             '--quiet --help --version'.split())

routes = re.search(r'static const GoalRoute goal_routes\[\] = \{(.*?)\n\};', main, re.S)
if not routes:
    print('cannot find goal_routes[] in %s' % src_path, file=sys.stderr)
    sys.exit(2)
route_titles = re.findall(r'"([^"]+)"\s*,\s*"', routes.group(1))
if len(route_titles) != 12:
    bad('route-count', 'the Goals front door lists %d routes, the design says 12'
        % len(route_titles))

steps = []
for arr in re.finditer(r'static const GoalStep (goal_steps_\w+)\[\] = \{(.*?)\n\};',
                       main, re.S):
    for row in re.finditer(r'\{\s*"([^"]+)"\s*,\s*"(--[a-z0-9-]+)"', arr.group(2)):
        steps.append((arr.group(1), row.group(1), row.group(2)))
if not steps:
    print('no Goals steps found in %s' % src_path, file=sys.stderr)
    sys.exit(2)

for table, module_id, verb in steps:
    if module_id not in modules:
        bad('goal-unknown-module', '%s names module "%s", which is not in the index'
            % (table, module_id))
        continue
    if verb in modules[module_id] or verb in EXEMPT:
        continue
    bad('goal-unknown-verb', '%s names "%s %s", which %s does not document'
        % (table, module_id, verb, module_id))

# ── promise 5: every verb a card can carry has a chip row ──────────────────
# The prerequisite and consequence tables are keyed by module and verb, and the
# interface refuses to guess: a verb that is in neither table gets no chips.
# This check is what makes that refusal safe -- it names the missing row while
# the page is still a diff rather than a card that quietly says nothing.
chips = re.search(r'static const ChipRow chip_rows\[\] = \{(.*?)\n\};', main, re.S)
if not chips:
    print('cannot find chip_rows[] in %s' % src_path, file=sys.stderr)
    sys.exit(2)
chip_rows = set()
for row in re.finditer(r'\{\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*(NEED_\w+)\s*,\s*(DOES_\w+)\s*\}',
                       chips.group(1)):
    chip_rows.add((row.group(1), row.group(2)))
if not chip_rows:
    print('chip_rows[] is empty in %s' % src_path, file=sys.stderr)
    sys.exit(2)

for module_id, verbs in sorted(modules.items()):
    for verb in sorted(verbs):
        if (module_id, verb) not in chip_rows:
            bad('no-chip-row', '%s %s has no prerequisite and consequence row'
                % (module_id, verb))

for table, module_id, verb in steps:
    if (module_id, verb) not in chip_rows and verb not in EXEMPT:
        bad('no-chip-row', 'Goals step "%s %s" (%s) has no chip row'
            % (module_id, verb, table))

entry_verbs = set()
for entry in re.finditer(r'static ModuleSubmenuEntry \*\w+_entries\[\] = \{(.*?)\n\};',
                         main, re.S):
    for v in re.finditer(r'--[a-z][a-z0-9-]*', entry.group(1)):
        entry_verbs.add(v.group(0))
for verb in sorted(entry_verbs):
    if not any(cv == verb for _cm, cv in chip_rows):
        bad('no-chip-row', 'a page offers %s, which no chip row covers' % verb)

# ── report ─────────────────────────────────────────────────────────────────
covered = len(harvest & set(dict_rows))
if jsonout:
    print(json.dumps({
        'keys': len(harvest),
        'covered': covered,
        'missing': len(missing),
        'dictionary': len(dict_rows),
        'unused': len(dead),
        'labels': len(labels),
        'steps': len(steps),
        'routes': len(route_titles),
        'chips': len(chip_rows),
        'entry_verbs': len(entry_verbs),
        'failures': [{'check': k, 'detail': d} for k, d in problems],
    }, indent=2))
else:
    if listall:
        for key in sorted(harvest):
            print('key   %-24s %s' % (key, dict_rows.get(key, '(no words)')))
        for kind, text in labels:
            print('label %-28s %s' % (kind, text))
        for table, module_id, verb in steps:
            print('step  %-20s %-20s %s' % (table, module_id, verb))
    print('keys %d covered %d missing %d · dictionary %d rows · %d labels · '
          '%d Goals steps over %d routes · %d chip rows'
          % (len(harvest), covered, len(missing), len(dict_rows), len(labels),
             len(steps), len(route_titles), len(chip_rows)))
    if problems:
        print()
        for kind, detail in problems:
            print('FAIL %s: %s' % (kind, detail))
        print()
        print('%d promise(s) broken' % len(problems))
    else:
        print('every rendered key has plain words, every row is reachable, '
              'every label names what it does, every Goals step names a verb '
              'its module documents')
sys.exit(1 if problems else 0)
PY
