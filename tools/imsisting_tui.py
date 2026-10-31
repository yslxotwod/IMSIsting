#!/usr/bin/env python3
"""Full-screen IMSIsting terminal workspace; stdlib curses only."""
from __future__ import annotations

import argparse
import curses
import os
import re
import shlex
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, replace
from pathlib import Path

APP_PAGES = ("Dashboard", "Live Traffic", "Casebook", "Stats", "Help")
CATEGORY_ICONS = {
    "SYSTEM": "⚙️",
    "RECON": "🔍",
    "RADIO": "📻",
    "ACCESS": "📶",
    "CORE NETWORK": "🌐",
    "SIM / IDENTITY": "💾",
    "BASEBAND / DEVICE": "📲",
    "TRACKING": "🛰️",
    "ANALYSIS": "ılı",
    "EXPLOIT KITS": "🪲",
    "INTERCEPT / CARRIER": "⚡",
}
DASHBOARD_HINTS = (("↑↓/jk", "modules"), ("Tab", "category"), ("Shift+Tab", "pages"),
                   ("/", "search"), ("Enter", "open"), ("?", "help"), ("q", "quit"))
WORKSPACE_HINTS = (("↑↓", "action"), ("←→", "module"), ("Enter", "run"), ("a", "arguments"),
                   ("f", "filter"), ("s", "save"), ("c", "clear"), ("Esc", "back"),
                   ("q", "quit"))
PAGE_HINTS = (("Shift+Tab", "next page"), ("Esc", "Dashboard"), ("q", "quit"))


@dataclass(frozen=True)
class Module:
    category: str
    key: str
    title: str
    function: str
    module_id: str
    verbs: tuple[str, ...] = ()
    groups: tuple[tuple[str, tuple[str, ...]], ...] = ()
    description: str = ""
    root: str = ""


@dataclass(frozen=True)
class Palette:
    """Every colour the workspace draws with, resolved once per terminal."""

    frame: int
    heading: int
    accent: int
    text: int
    ok: int
    bad: int
    key: int


@dataclass
class ActionRun:
    process: subprocess.Popen[bytes]
    command: tuple[str, ...]


# ───────────────────────────── C reading ─────────────────────────────
#
# The GUI is the authority on how a module is published: its one-line
# description lives in the MODULE TABLE, and its view names and the verbs each
# view puts on screen live in that module's submenu table and page builders.
# The TUI reads those tables instead of keeping a second copy of them, so a
# view renamed in the GUI is renamed here on the next launch.

_COMMENT_OR_LITERAL = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'", re.S)
_BLANKABLE = re.compile(r"[^\n]")
_ARRAY = re.compile(r"static ModuleSubmenuEntry (\w+)_entries\[\] = \{(.*?)^\};", re.M | re.S)
_REGISTRY = re.compile(r'module_registry_register\("([^"]+)",\s*(\w+)_entries')
_ENTRY = re.compile(r'\{\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*(NULL|(?:"(?:[^"\\]|\\.)*"\s*)+)'
                    r'(?:\s*,\s*(\w+))?\s*\}')
_TABLE = re.compile(r"static const ModuleDefinition modules\[\] = \{(.*?)^\};", re.M | re.S)
_DESCRIBED = re.compile(r'\{\s*"(\w+)"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*'
                        r'((?:"(?:[^"\\]|\\.)*"\s*)+)\}')
_VERB = re.compile(r"--[a-z][a-z0-9-]*")

# Verbs that take an argument, shared with tools/check-verbs.sh so the action
# list cannot offer `--transport ssh` as something to press. A verb in that file
# is never dispatched on its own anywhere in the tree, which is exactly what
# makes it safe to keep out of a list of things to run.
MODIFIERS = frozenset(
    line.strip() for line in
    (Path(__file__).resolve().parent / "verb-modifiers.txt").read_text(
        encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#"))


def c_sanitize(source: str, blank_literals: bool) -> str:
    """Blank comments (and optionally string bodies) while keeping offsets.

    Reading verbs out of a page builder is only honest if comments and prose
    cannot contribute any: a builder that mentions `--plan` in a comment must
    not put `--plan` in the workspace. Blanking replaces every character with
    a space and keeps newlines, so indices still line up with the raw file.
    """
    def blank(text: str) -> str:
        return _BLANKABLE.sub(" ", text)

    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        if text[0] in "\"'":
            return blank(text) if blank_literals else text
        return blank(text)

    return _COMMENT_OR_LITERAL.sub(replace, source)


_DEFINITION = re.compile(r"(?m)^(\w+)\s*\(")


def c_function_spans(code: str) -> dict[str, tuple[int, int]]:
    """Locate every column-zero function definition in blanked source.

    One pass, so a module table that names two hundred builders costs one
    scan rather than two hundred searches over a thirty-thousand-line file.
    """
    spans: dict[str, tuple[int, int]] = {}
    for match in _DEFINITION.finditer(code):
        name = match.group(1)
        if name in spans:
            continue
        start = code.find("{", match.end())
        if start < 0:
            continue
        depth = 0
        for index in range(start, len(code)):
            char = code[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    spans[name] = (start, index + 1)
                    break
    return spans


def literal_text(raw: str) -> str:
    """Join adjacent C string literals into the sentence a reader sees."""
    return " ".join("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', raw)).split())


def spec_groups(spec: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Read one GUI spec string into its named sections.

    Spec grammar (see ModuleSubmenuEntry in main.c): buttons are packed as
    "verb[:Label][!]" separated by '|', a leading '~' marks a verb that needs
    an argument, and a token starting with '#' opens a named section.
    """
    sections: list[tuple[str, list[str]]] = []
    for token in spec.split("|"):
        token = token.strip()
        if not token:
            continue
        if token.startswith("#"):
            sections.append((token.lstrip("#").strip(), []))
            continue
        if not sections:
            sections.append(("", []))
        verb = token.lstrip("~").split(":")[0].rstrip("!")
        if _VERB.fullmatch(verb):
            sections[-1][1].append(verb)
    return tuple((name, tuple(verbs)) for name, verbs in sections if verbs)


def parse_gui(root: Path) -> tuple[dict[str, str], dict[str, tuple[tuple[str, tuple[str, ...]], ...]]]:
    """One pass over the GUI source: descriptions by module, views by module."""
    path = root / "native/src/main1.c"
    if not path.is_file():
        return {}, {}
    source = path.read_text(encoding="utf-8", errors="replace")
    prose = c_sanitize(source, blank_literals=False)
    code = c_sanitize(source, blank_literals=True)

    table = _TABLE.search(prose)
    descriptions = {module_id: literal_text(raw)
                    for module_id, raw in _DESCRIBED.findall(table.group(1))} if table else {}

    arrays = dict(_ARRAY.findall(prose))
    spans = c_function_spans(code)
    views: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {}
    for module_id, array in _REGISTRY.findall(prose):
        body = arrays.get(array)
        if body is None:
            continue
        groups: list[tuple[str, tuple[str, ...]]] = []
        for name, _icon, spec, builder in _ENTRY.findall(body):
            if spec.strip() == "NULL":
                start, end = spans.get(builder or "", (0, 0))
                verbs = tuple(dict.fromkeys(_VERB.findall(prose[start:end])))
                # An empty group is kept on purpose: the view exists, it is drawn
                # by the GUI, and the terminal says so rather than pretending the
                # module has fewer views than it does.
                groups.append((name, verbs))
                continue
            sections = spec_groups(literal_text(spec))
            for section, verbs in sections:
                groups.append((f"{name} · {section}" if section else name, verbs))
        views[module_id] = tuple(groups)
    return descriptions, views


def parse_table_text(text: str, root: str = "") -> list[Module]:
    """Read the launcher's navigation table into modules, without sourcing it.

    Kept as its own function because the launcher table is the only place the
    menu order lives: the check that every module listed there has a script on
    disk reads this and nothing else.
    """
    modules: list[Module] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('"') and line.endswith('"'):
            fields = line[1:-1].split("|")
            if len(fields) >= 5:
                modules.append(Module(*fields[:5], root=root))
    return modules


def parse_table_tsv(path: Path) -> list[Module]:
    """Read a combined toolkit table TSV into modules.

    Format (tab-separated):
      root    key    category    title    function    module_id
    """
    modules: list[Module] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) >= 6:
            modules.append(Module(category=fields[2], key=fields[1],
                                  title=fields[3], function=fields[4],
                                  module_id=fields[5], root=fields[0]))
    return modules


def parse_modules(root: Path) -> list[Module]:
    """Read launcher navigation and generated verb index without sourcing it.

    Sourcing imsisting.sh from Enter was the old behaviour: it loaded every
    module then handed control to its legacy CLI menu.  The TUI instead runs a
    chosen module script directly and keeps its output in the workspace.
    """
    text = (root / "imsisting.sh").read_text(encoding="utf-8")
    start = text.index("IMSISTING_MODULE_TABLE=(")
    end = text.index("\n)", start)
    modules = parse_table_text(text[start:end])
    verbs: dict[str, tuple[str, ...]] = {}
    for line in (root / "module_index.tsv").read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) >= 4:
            verbs[fields[0]] = tuple(v for v in fields[3].split() if v.startswith("--"))
    descriptions, views = parse_gui(root)
    return [replace(module, verbs=verbs.get(module.module_id, ()),
                    groups=views.get(module.module_id, ()),
                    description=descriptions.get(module.module_id, ""))
            for module in modules]


def colours() -> Palette:
    if not curses.has_colors():
        return Palette(*(curses.A_BOLD,) * 7)
    curses.start_color(); curses.use_default_colors()
    roles = (("frame", curses.COLOR_BLUE, False), ("heading", curses.COLOR_MAGENTA, True),
             ("accent", curses.COLOR_BLUE, True), ("text", curses.COLOR_WHITE, False),
             ("ok", curses.COLOR_GREEN, False), ("bad", curses.COLOR_RED, True),
             ("key", curses.COLOR_YELLOW, True))
    attrs = {}
    for pair, (name, colour, bold) in enumerate(roles, 1):
        curses.init_pair(pair, colour, -1)
        attrs[name] = curses.color_pair(pair) | (curses.A_BOLD if bold else 0)
    return Palette(**attrs)


def put(win, y, x, text, attr=0):
    height, width = win.getmaxyx()
    if 0 <= y < height and x < width:
        try: win.addnstr(y, max(0, x), text, max(0, width - max(0, x) - 1), attr)
        except curses.error: pass


def clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[:max(0, width - 1)] + "…"


def panel_frame(win, width, height, frame):
    put(win, 0, 0, "╭" + "─" * max(0, width - 2) + "╮", frame)
    put(win, height - 1, 0, "╰" + "─" * max(0, width - 2) + "╯", frame)


def prompt(win, label: str, initial: str = "") -> str:
    h, w = win.getmaxyx(); x = len(label) + 4
    curses.echo()
    try: curses.curs_set(1)
    except curses.error: pass
    win.move(h - 2, 2); win.clrtoeol(); put(win, h - 2, 2, label + ": ")
    put(win, h - 2, x, initial); win.move(h - 2, x + len(initial))
    try:
        return win.getstr(h - 2, x, max(1, w - x - 3)).decode("utf-8", "replace")
    finally:
        curses.noecho()
        try: curses.curs_set(0)
        except curses.error: pass


def application_menu(app_index: int, width: int) -> str:
    items = "  ".join(f"[{name}]" if i == app_index else name
                      for i, name in enumerate(APP_PAGES))
    return clip(items, width)


def verb_title(verb: str) -> str:
    """Turn a CLI flag into the label an operator expects to read."""
    return verb.removeprefix("--").replace("-", " ").title()


def _strip_prefix(category: str) -> str:
    """Strip a toolkit prefix like 'imsisting:' from a category name."""
    idx = category.find(":")
    return category[idx + 1:] if idx >= 0 else category


def category_title(category: str) -> str:
    raw = _strip_prefix(category)
    return f"[{CATEGORY_ICONS.get(raw, '•')} ] {category}"


def module_script(module: Module, global_root: Path) -> Path:
    """Return the script file for a module.

    If the module has a root field, use that; otherwise fall back to the
    global root.  This lets a TUI launched from one toolkit run modules from
    another without changing how the TUI is called.
    """
    real_root = Path(module.root) if module.root else global_root
    return real_root / "modules" / f"{module.module_id}.sh"


def module_title(module: Module) -> str:
    raw = _strip_prefix(module.category)
    return f"[{CATEGORY_ICONS.get(raw, '•')} ] {module.title}"


def grouped_actions(module: Module) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Place CLI actions beneath the same named views used by the GUI."""
    actions = tuple(v for v in module.verbs
                    if v not in ("--menu", "--help")
                    and v[2:] not in MODIFIERS)
    if not actions:
        # For modules whose verbs were never indexed (websting, unindexed),
        # show the two verbs every module supports.
        actions = ("--help", "--selftest")
    pending = set(actions)
    groups: list[tuple[str, tuple[str, ...]]] = []
    for title, gui_verbs in module.groups:
        members = tuple(v for v in actions if v in pending and v in gui_verbs)
        if members:
            groups.append((title, members))
            pending.difference_update(members)
    if pending:
        fallback = "Other actions" if module.groups else "Actions"
        groups.append((fallback, tuple(v for v in actions if v in pending)))
    return tuple(groups)


def action_rows(module: Module) -> tuple[tuple[str, str], ...]:
    """The action pane as printed: a heading row per view, then its actions."""
    return tuple((kind, text)
                 for title, verbs in grouped_actions(module)
                 for kind, text in (("group", title), *(("action", verb) for verb in verbs)))


def header_fields(root: Path, run: ActionRun | None) -> tuple[tuple[str, str], ...]:
    """State line as label/value pairs, so the values can carry their own colour."""
    def value(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace").strip() if path.is_file() else ""
    # Imsting-specific fields (TARGET, CASE) are only meaningful when
    # the toolkit launcher owns these paths.  In --table-tsv mode they
    # are clutter, so we skip them.
    if os.environ.get("STINGLAB_COMBINED"):
        return (("TASK", verb_title(run.command[2]) if run else "idle"),)
    target = ""
    for directory in (Path(os.environ.get("TMP_DIR", "/tmp/imsisting")), root / "tmp"):
        target = " ".join(value(directory / name) for name in ("target_rat", "target_arfcn", "target_plmn")
                          if value(directory / name))
        if target: break
    case = value(root / "state/casebook/active_case") or "none"
    task = verb_title(run.command[2]) if run else "idle"
    return (("TARGET", target or "none"), ("CASE", case), ("TASK", task))


def state_text(fields: tuple[tuple[str, str], ...]) -> str:
    return "  ".join(f"{label}: {value}" for label, value in fields)


def put_state(win, y, right, fields, palette, left_edge=2) -> int:
    """Right-align the state line: values yellow, labels in the frame colour."""
    x = max(left_edge, right - len(state_text(fields)) - 3)
    for label, value in fields:
        put(win, y, x, f"{label}: ", palette.frame); x += len(label) + 2
        put(win, y, x, clip(value, max(0, right - x - 2)), palette.key); x += len(value) + 2
    return x


def put_hints(win, y, x, hints, palette, width):
    """Key hints: the key you press reads yellow, what it does reads frame."""
    cursor = x
    for keys, label in hints:
        if cursor + len(keys) + len(label) + 2 > x + width:
            break
        put(win, y, cursor, keys, palette.key); cursor += len(keys)
        put(win, y, cursor, " " + label, palette.frame); cursor += len(label) + 2


def spinner(run: ActionRun | None) -> str:
    return "|/-\\"[int(time.monotonic() * 8) % 4] if run else ""


def detail_rows(module: Module | None, root: Path, width: int) -> list[tuple[str, str]]:
    """What the empty half of the dashboard says about the selected module."""
    if module is None:
        return [("text", "no module matches the current filter")]
    script = module_script(module, root)
    groups = grouped_actions(module)
    rows: list[tuple[str, str]] = [("title", module_title(module)),
                                  ("meta", f"{module.module_id}  ·  {module.category}"),
                                  ("meta", ("unknown actions" if not module.verbs
                                            else f"{len(module.verbs)} actions")
                                           + "  ·  " + ("script present" if script.is_file() else "script missing"))]

    if module.description:
        rows.append(("gap", ""))
        rows.extend(("text", line) for line in textwrap.wrap(module.description, max(12, width)))
    gui_only = [name for name, verbs in module.groups if not verbs]
    if groups or gui_only:
        rows.append(("gap", ""))
        rows.append(("sub", "VIEWS"))
        for title, verbs in groups:
            rows.extend(("text", line) for line in
                        textwrap.wrap(f"{title}  ({len(verbs)})", max(12, width)))
        for name in gui_only:
            rows.extend(("text", line) for line in
                        textwrap.wrap(f"{name}  (in the GUI)", max(12, width)))
    return rows


def dashboard(win, modules, root, version, app_index, category, query, selected, scroll, note, run, palette):
    win.erase(); h, w = win.getmaxyx(); panel_frame(win, w, h, palette.frame)
    categories = ["ALL"] + list(dict.fromkeys(m.category for m in modules))
    matches = [m for m in modules if (category == "ALL" or m.category == category)
               and query.casefold() in f"{m.key} {m.title} {m.module_id} {m.category} "
                                       f"{m.description}".casefold()]
    selected = min(selected, max(0, len(matches) - 1))
    left = max(26, min(35, w // 3)); top, footer = 5, h - 4; visible = max(1, footer - top)
    detail_width = max(0, min(60, (w - left) // 2)) if w >= 92 else 0
    module_width = w - left - detail_width - (2 if detail_width else 0)
    scroll = min(scroll, max(0, len(matches) - visible))
    if selected < scroll: scroll = selected
    if selected >= scroll + visible: scroll = selected - visible + 1
    identity = f"IMSISTING v{version}  TUI"
    menu = application_menu(app_index, max(0, w - len(identity) - 7))
    put(win, 1, 2, identity, palette.accent)
    put(win, 1, max(len(identity) + 5, w - len(menu) - 3), menu, palette.accent)
    fields = header_fields(root, run)
    chosen = matches[selected] if matches else None
    detail = (f"MODULE: {module_title(chosen)}  ·  {len(chosen.verbs)} actions"
              if chosen else "MODULE: no match")
    state_left = max(2, w - len(state_text(fields)) - 3)
    put(win, 2, 2, clip(detail, max(0, state_left - 4)), palette.text)
    put_state(win, 2, w - 1, fields, palette)
    put(win, 3, 0, "├" + "─" * max(0, w - 2) + "┤", palette.frame)
    put(win, 4, 2, "CATEGORIES", palette.heading); put(win, 4, left + 2, "MODULES", palette.heading)
    for y in range(4, footer):
        put(win, y, left, "│", palette.frame); put(win, y, w - 1, "│", palette.frame)
        if detail_width: put(win, y, w - detail_width - 1, "│", palette.frame)
    if detail_width: put(win, 4, w - detail_width + 1, "MODULE DETAIL", palette.heading)
    for i, cat in enumerate(categories[:max(1, footer - 5)]):
        label = "[• ] ALL" if cat == "ALL" else category_title(cat)
        put(win, 5 + i, 2, clip(label, left - 4),
            curses.A_REVERSE if cat == category else palette.text)
    for i, m in enumerate(matches[scroll:scroll + visible]):
        present = module_script(m, root).is_file()
        attr = (curses.A_REVERSE if scroll + i == selected
                else (palette.ok if present else palette.bad))
        put(win, top + i, left + 2,
            clip(f"{m.key:>2}  {'●' if present else '○'}  {module_title(m)}", module_width - 3), attr)
    if detail_width:
        rows = detail_rows(chosen, root, detail_width - 4)
        for i, (kind, text) in enumerate(rows[:max(0, footer - 6)]):
            attr = {"title": palette.accent, "meta": palette.text, "text": palette.text,
                    "sub": palette.heading}.get(kind, palette.text)
            put(win, 6 + i, w - detail_width, clip(text, detail_width - 2), attr)
    put(win, footer, 0, "├" + "─" * max(0, w - 2) + "┤", palette.frame)
    put(win, footer + 1, 2, "SEARCH  " + (query or "type to filter modules"), palette.text)
    if note: put(win, footer + 2, 2, clip(note, w - 4), palette.frame)
    else: put_hints(win, footer + 2, 2, DASHBOARD_HINTS, palette, w - 4)
    return matches, selected, scroll, categories


def stats_rows(root: Path) -> list[tuple[str, str, str, str, str, str, str]]:
    """Read the stats index the GUI draws from: one table, one source per row."""
    path = root / "loot" / "stats" / "index.tsv"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) >= 7:
            rows.append(tuple(fields[:7]))
    return rows


def stats_page(win, root: Path, palette) -> None:
    """Fleet numbers, then every module that has something to report.

    The index drops zero values on purpose: a zero is an empty shelf, not a
    measurement, and a page of zeros reads as data when there is none.
    """
    h, w = win.getmaxyx()
    rows = stats_rows(root)
    fleet = [row for row in rows if row[0] == "fleet"]
    modules = [row for row in rows if row[0] != "fleet"]
    put(win, 5, 3, "STATS  ·  every number names its source", palette.heading)
    y = 6
    for _scope, _module, _key, label, value, unit, source in fleet:
        if y >= h - 4: return
        text = f"{value} {unit}".strip()
        put(win, y, 3, clip(label, 30), palette.text)
        put(win, y, 34, clip(text, 14), palette.key)
        put(win, y, 50, clip(source, max(8, w - 54)), palette.frame)
        y += 1
    if not modules:
        put(win, y + 1, 3, "No module has data yet — run a module and come back.", palette.text)
        return
    y += 1
    put(win, y, 3, f"{len(modules)} module readings with data", palette.heading)
    y += 1
    for index, (_scope, module, _key, label, value, unit, _source) in enumerate(modules):
        if y >= h - 4:
            put(win, h - 4, 3, f"… {len(modules) - index} more", palette.frame)
            return
        text = f"{value} {unit}".strip()
        put(win, y, 3, clip(f"{module}", 12), palette.frame)
        put(win, y, 16, clip(label, 32), palette.text)
        put(win, y, 50, clip(text, max(6, w - 54)), palette.key)
        y += 1


def utility_page(win, root, version, app_index, note, run, palette):
    """Small TUI-native landing pages for the global navigation menu."""
    win.erase(); h, w = win.getmaxyx(); panel_frame(win, w, h, palette.frame)
    identity = f"IMSISTING v{version}  TUI"
    menu = application_menu(app_index, max(0, w - len(identity) - 7))
    put(win, 1, 2, identity, palette.accent)
    put(win, 1, max(len(identity) + 5, w - len(menu) - 3), menu, palette.accent)
    put_state(win, 2, w - 1, header_fields(root, run), palette)
    put(win, 3, 0, "├" + "─" * max(0, w - 2) + "┤", palette.frame)
    page = APP_PAGES[app_index]
    content = {
        "Live Traffic": ["LIVE TRAFFIC", "Open a module workspace and select GSMTAP Live Feed to inspect and process live traffic."],
        "Casebook": ["CASEBOOK", f"Case data is stored in {root / 'cases'}.", "Use the GUI Casebook for evidence editing; this TUI keeps module operations in one place."],
        "Stats": ["STATS", f"{len(list((root / 'modules').glob('*.sh')))} module scripts available.", f"{len(list((root / 'cases').glob('*')))} case entries in the current workspace."],
        "Help": ["HELP", "Shift+Tab cycles application pages. Tab cycles module categories on Dashboard.", "Enter opens a module workspace. Its output stays above the action selection menu."],
    }[page]
    if page == "Stats":
        stats_page(win, root, palette)
    else:
        put(win, 5, 3, content[0], palette.heading)
        for i, line in enumerate(content[1:]):
            put(win, 7 + i * 2, 3, clip(line, w - 6), palette.text)
    put(win, h - 3, 0, "├" + "─" * max(0, w - 2) + "┤", palette.frame)
    if note: put(win, h - 2, 2, clip(note, w - 4), palette.frame)
    else: put_hints(win, h - 2, 2, PAGE_HINTS, palette, w - 4)


def workspace(win, modules, current, cat, mod_pos, action_pos, output, args, output_filter, running, note, palette, version, root):
    """Three panes: left navigation, output above and action selection below."""
    win.erase(); h, w = win.getmaxyx(); panel_frame(win, w, h, palette.frame)
    left = max(26, min(35, w // 3)); rx = left + 1; action_top = h - max(7, h // 3) - 3
    category_modules = [m for m in modules if m.category == cat]
    rows = action_rows(current)
    actions = tuple(text for kind, text in rows if kind == "action")
    action_pos = max(0, min(action_pos, len(actions) - 1))
    put(win, 1, 2, f"IMSISTING v{version}  TUI", palette.accent)
    put(win, 1, rx + 1, clip(f"{module_title(current)}  /  {current.category}", w - rx - 16), palette.heading)
    state = f"{spinner(running)} RUNNING" if running else "READY"
    put(win, 1, w - len(state) - 3, state, palette.ok if running else palette.key)
    fields = header_fields(root, running)
    state_left = max(rx + 1, w - len(state_text(fields)) - 3)
    put(win, 2, rx + 1, clip(current.description, max(0, state_left - rx - 3)), palette.text)
    put_state(win, 2, w - 1, fields, palette)
    put(win, 3, 0, "├" + "─" * max(0, w - 2) + "┤", palette.frame)
    put(win, 4, 2, "MODULE NAVIGATOR", palette.heading)
    put(win, 4, rx + 1, "COMMAND OUTPUT", palette.heading)
    put_hints(win, 4, rx + 16, (("f", "filter"), ("s", "save"), ("c", "clear"),
                                ("/", "search")), palette, w - rx - 17)
    for y in range(4, h - 2): put(win, y, left, "│", palette.frame); put(win, y, w - 1, "│", palette.frame)
    y = 5
    for name in dict.fromkeys(m.category for m in modules):
        put(win, y, 2, clip(category_title(name), left - 4),
            curses.A_REVERSE if name == cat else palette.text); y += 1
    y += 1; put(win, y, 2, "MODULES", palette.frame); y += 1
    for i, m in enumerate(category_modules):
        if y >= h - 2: break
        put(win, y, 2, clip(f"{'›' if m.module_id == current.module_id else ' '} {m.key:>2}  {module_title(m)}", left - 4),
            curses.A_REVERSE if i == mod_pos else palette.text); y += 1
    max_out = max(1, action_top - 5)
    shown = [line for line in output if output_filter.casefold() in line.casefold()]
    for i, line in enumerate((shown[-max_out:] or ["Select an action below to run it here."])):
        put(win, 5 + i, rx + 1, clip(line, w - rx - 3), palette.text)
    put(win, action_top, rx, "├" + "─" * max(0, w - rx - 2) + "┤", palette.frame)
    put(win, action_top + 1, rx + 1, "MODULE ACTIONS", palette.heading)
    visible = max(1, h - action_top - 5)
    selected_row = [i for i, (kind, _) in enumerate(rows) if kind == "action"][action_pos:action_pos + 1]
    selected_row = selected_row[0] if selected_row else 0
    start = 0 if len(rows) <= visible else max(0, min(selected_row - visible + 1, len(rows) - visible))
    start = min(start, selected_row)
    for i, (kind, text) in enumerate(rows[start:start + visible]):
        if kind == "group":
            put(win, action_top + 2 + i, rx + 1, clip(f"▸ {text}", w - rx - 4), palette.heading)
        else:
            put(win, action_top + 2 + i, rx + 3, clip(verb_title(text), w - rx - 6),
                curses.A_REVERSE if start + i == selected_row else palette.text)
    filter_label = f"  FILTER: {output_filter}" if output_filter else ""
    put(win, h - 3, rx + 1, clip("ARGS  " + (args or "(none)") + filter_label, w - rx - 3), palette.frame)
    if note: put(win, h - 2, 2, clip(note, w - 4), palette.ok if running else palette.frame)
    else: put_hints(win, h - 2, 2, WORKSPACE_HINTS, palette, w - 4)
    return category_modules, actions, action_pos


def start_action(_root, module, action, args):
    script = module_script(module, _root)
    command = ("bash", str(script), action, *shlex.split(args))
    cwd = script.parent.parent  # the toolkit root where the module lives
    proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    assert proc.stdout is not None; os.set_blocking(proc.stdout.fileno(), False)
    return ActionRun(proc, command)


def poll(run, output):
    if run is None or run.process.stdout is None: return run
    def read():
        try: return os.read(run.process.stdout.fileno(), 65536)
        except BlockingIOError: return b""
    chunk = read()
    if chunk: output.extend(chunk.decode("utf-8", "replace").replace("\r", "").splitlines())
    if run.process.poll() is None: return run
    while chunk:
        chunk = read()
        if chunk: output.extend(chunk.decode("utf-8", "replace").replace("\r", "").splitlines())
    output.append(f"[process exited with status {run.process.returncode}]")
    run.process.stdout.close(); return None


def save_output(root: Path, output: list[str]) -> Path:
    logs = root / "logs"; logs.mkdir(parents=True, exist_ok=True)
    path = logs / f"tui-output-{time.strftime('%Y%m%d-%H%M%S')}.log"
    path.write_text("\n".join(output) + "\n", encoding="utf-8")
    return path


def help_screen(win):
    win.erase(); h, w = win.getmaxyx()
    lines = ["FIELD CONSOLE / KEYBOARD MAP", "", "Dashboard: ↑↓ select · Tab category · / search · Enter workspace",
             "Workspace: ↑↓ action · ←→ module · a arguments · Enter run", "", "Output remains above the action menu.", "Press any key to return."]
    for i, line in enumerate(lines): put(win, (h - len(lines)) // 2 + i, max(0, (w - len(line)) // 2), line, curses.A_BOLD if not i else 0)
    win.refresh(); win.getch()


def run_tui(win, modules, root, version):
    try: curses.curs_set(0)
    except curses.error: pass
    win.keypad(True); win.timeout(80); palette = colours()
    cat, query, selected, scroll, current, mod_pos, action_pos = "ALL", "", 0, 0, None, 0, 0
    app_index = 0
    output, args, output_filter, running, note = [], "", "", None, ""
    categories = ["ALL"] + list(dict.fromkeys(m.category for m in modules))
    while True:
        running = poll(running, output)
        if current is None and app_index == 0:
            matches, selected, scroll, categories = dashboard(
                win, modules, root, version, app_index, cat, query, selected, scroll, note, running, palette)
        elif current is None:
            utility_page(win, root, version, app_index, note, running, palette)
        else:
            nav, actions, action_pos = workspace(
                win, modules, current, cat, mod_pos, action_pos, output, args, output_filter,
                running, note, palette, version, root)
        note = ""; win.refresh(); ch = win.getch()
        if ch == -1: continue
        if ch in (ord("q"), ord("Q")):
            if running: running.process.terminate()
            return 0
        if ch in (ord("?"), ord("h")):
            win.timeout(-1); help_screen(win); win.timeout(80); continue
        if current is None and ch == curses.KEY_BTAB:
            app_index = (app_index + 1) % len(APP_PAGES)
            continue
        if current is None:
            if app_index != 0:
                if ch == 27: app_index = 0
                continue
            if ch in (curses.KEY_UP, ord("k")): selected = max(0, selected - 1)
            elif ch in (curses.KEY_DOWN, ord("j")): selected = min(max(0, len(matches) - 1), selected + 1)
            elif ch == 9: cat = categories[(categories.index(cat) + 1) % len(categories)]; selected = scroll = 0
            elif ch == ord("/"):
                win.timeout(-1); query = prompt(win, "SEARCH", query); win.timeout(80); selected = scroll = 0
            elif ch in (curses.KEY_BACKSPACE, 127, 8): query = query[:-1]; selected = scroll = 0
            elif ch in (curses.KEY_ENTER, 10, 13) and matches:
                current = matches[selected]; cat = current.category
                mod_pos = [m.module_id for m in modules if m.category == cat].index(current.module_id)
                action_pos = 0; output_filter = ""; output = [f"Opened {current.title}.", "Choose a module action below."]
            elif 32 <= ch <= 126 and chr(ch).isalnum(): query += chr(ch).lower(); selected = scroll = 0
            continue
        if ch == 27:
            current = None
            if running is None: output = []
        elif ch in (curses.KEY_LEFT, ord("[")):
            mod_pos = max(0, mod_pos - 1); current = nav[mod_pos]; action_pos = 0; output_filter = ""; output = [f"Opened {current.title}."]
        elif ch in (curses.KEY_RIGHT, ord("]")):
            mod_pos = min(len(nav) - 1, mod_pos + 1); current = nav[mod_pos]; action_pos = 0; output_filter = ""; output = [f"Opened {current.title}."]
        elif ch in (curses.KEY_UP, ord("k")): action_pos = max(0, action_pos - 1)
        elif ch in (curses.KEY_DOWN, ord("j")): action_pos = min(len(actions) - 1, action_pos + 1)
        elif ch in (ord("a"), ord("A")):
            win.timeout(-1); args = prompt(win, "ARGUMENTS", args); win.timeout(80)
        elif ch in (ord("f"), ord("F")):
            win.timeout(-1); output_filter = prompt(win, "OUTPUT FILTER", output_filter); win.timeout(80)
        elif ch in (ord("s"), ord("S")):
            path = save_output(root, output); note = f"Saved output to {path.relative_to(root)}"
        elif ch in (ord("c"), ord("C")): output = []
        elif ch == ord("/"):
            win.timeout(-1); output_filter = prompt(win, "OUTPUT FILTER", output_filter); win.timeout(80)
        elif ch in (curses.KEY_ENTER, 10, 13):
            if running: note = "A command is already running."
            else:
                try:
                    running = start_action(root, current, actions[action_pos], args)
                    output.extend(["", "$ " + " ".join(shlex.quote(p) for p in running.command)])
                except (OSError, ValueError) as error: note = f"Could not start command: {error}"


def main():
    parser = argparse.ArgumentParser(description="IMSIsting full-screen terminal workspace")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--table-tsv", type=Path, default=None,
                        help="Combined toolkit table (root\\tkey\\tcategory\\ttitle\\tfunction\\tmodule_id)")
    parser.add_argument("--version", action="version",
                        version=os.environ.get("IMSISTING_VERSION", "IMSIsting"))
    args = parser.parse_args()
    root = args.root
    table_tsv = args.table_tsv
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get("TERM") in ("", "dumb"):
        print("IMSIsting TUI needs an interactive terminal (TTY). Use --help, --list, or --gui.",
              file=sys.stderr); return 2

    if table_tsv is not None:
        modules = parse_table_tsv(table_tsv)
        # Enrich each module with verbs, views and descriptions from its own toolkit root
        for tk_root in list(dict.fromkeys(m.root for m in modules)):
            if not tk_root:
                continue
            r = Path(tk_root)
            verbs: dict[str, tuple[str, ...]] = {}
            idx = r / "module_index.tsv"
            if idx.is_file():
                for line in idx.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                    fields = line.split("\t")
                    if len(fields) >= 4:
                        verbs[fields[0]] = tuple(v for v in fields[3].split()
                                                  if v.startswith("--"))
            descriptions, views = parse_gui(r)
            modules = [replace(m, verbs=verbs.get(m.module_id, ()),
                               groups=views.get(m.module_id, ()),
                               description=descriptions.get(m.module_id, ""))
                       if m.root == tk_root else m
                       for m in modules]
        # Version: compact toolkits summary
        toolkits = sorted({Path(m.root).name for m in modules if m.root})
        tk_label = " + ".join(toolkits)
        version = f"stinglab ({tk_label})"
    else:
        modules = parse_modules(root)
        version_file = root / "VERSION"
        version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "unknown"

    return curses.wrapper(run_tui, modules, root, version)


if __name__ == "__main__": raise SystemExit(main())
