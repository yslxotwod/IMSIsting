#!/usr/bin/env python3
"""IMSIsting full-screen terminal dashboard (stdlib curses only)."""
from __future__ import annotations
import argparse
import curses
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Module:
    category: str
    key: str
    title: str
    function: str
    module_id: str


def parse_table_text(text: str) -> list[Module]:
    modules=[]
    for line in text.splitlines():
        line=line.strip()
        if not line.startswith('"') or not line.endswith('"'): continue
        cols=line[1:-1].split('|')
        if len(cols)>=5: modules.append(Module(*cols[:5]))
    return modules


def draw(stdscr, modules: list[Module], query: str, selected: int, scroll: int,
         category: str, message: str, root: Path):
    stdscr.erase()
    h,w=stdscr.getmaxyx()
    def put(y,x,text,attr=0):
        if 0 <= y < h and x < w:
            try: stdscr.addnstr(y,max(0,x),text,max(0,w-max(0,x)-1),attr)
            except curses.error: pass
    if curses.has_colors():
        curses.start_color(); curses.use_default_colors()
        for i,fg in enumerate((curses.COLOR_CYAN,curses.COLOR_MAGENTA,curses.COLOR_YELLOW,curses.COLOR_GREEN,curses.COLOR_WHITE),1):
            curses.init_pair(i,fg,-1)
        cyan=curses.color_pair(1)|curses.A_BOLD; mag=curses.color_pair(2)|curses.A_BOLD
        yellow=curses.color_pair(3)|curses.A_BOLD; green=curses.color_pair(4); white=curses.color_pair(5)
    else:
        cyan=mag=yellow=curses.A_BOLD; green=white=0
    reverse=curses.A_REVERSE
    cats=["ALL"]+list(dict.fromkeys(m.category for m in modules))
    filtered=[m for m in modules if (category=="ALL" or m.category==category) and query.casefold() in f"{m.key} {m.title} {m.module_id} {m.category}".casefold()]
    selected=min(selected,max(0,len(filtered)-1))

    if h < 24 or w < 78:
        put(0,0,"IMSIsting / MODULE CONSOLE",cyan)
        put(1,0,"Search: "+(query or "type to filter"),white)
        put(2,0,"Category: "+category,mag)
        page=max(1,h-7)
        if selected<scroll: scroll=selected
        if selected>=scroll+page: scroll=selected-page+1
        for i,m in enumerate(filtered[scroll:scroll+page]):
            put(4+i,1,f"{'›' if scroll+i==selected else ' '} {m.key:>2}  {m.title}",reverse if scroll+i==selected else white)
        put(h-2,0,message or "↑↓ move  Enter open  / search  Tab category  q quit",cyan)
        return filtered,selected,scroll

    # Header: crisp instrument-panel frame.
    put(0,0,"╭"+"─"*(w-2)+"╮",cyan)
    put(0,3," IMSISTING  /  FIELD OPERATIONS CONSOLE ",cyan)
    put(1,2,"▰  CELLULAR SYSTEMS     GSM · UMTS · LTE · NR",mag)
    right=f"v{os.environ.get('IMSISTING_VERSION','')}  /  {len(modules):02d} MODULES"
    put(1,w-len(right)-3,right,yellow)
    put(2,0,"├"+"─"*(w-2)+"┤",cyan)

    # Category tabs.
    x=2
    for cat in cats:
        label=f" {cat} "
        if x+len(label)>=w-2: break
        put(3,x,label,reverse if cat==category else white); x+=len(label)+1
    put(4,0,"├"+"─"*(w-2)+"┤",cyan)

    # Layout: left module index, right live detail card.
    split=max(46,min(64,w//2))
    put(5,2,"MODULE INDEX",mag); put(5,split+2,"MODULE BRIEF",mag)
    put(6,0,"│",cyan); put(6,split,"┆",cyan); put(6,w-1,"│",cyan)
    visible=max(1,h-14)
    if selected<scroll: scroll=selected
    if selected>=scroll+visible: scroll=selected-visible+1
    for row,m in enumerate(filtered[scroll:scroll+visible]):
        y=7+row
        state="●" if (root/"modules"/f"{m.module_id}.sh").is_file() else "○"
        text=f" {m.key:>2}  {state}  {m.title}"
        put(y,1,text[:split-3],reverse if scroll+row==selected else (green if state=="●" else white))
        put(y,split,"┆",cyan); put(y,w-1,"│",cyan)
    for y in range(7+visible,h-5):
        put(y,split,"┆",cyan); put(y,w-1,"│",cyan)

    if filtered:
        m=filtered[selected]
        stat="AVAILABLE" if (root/"modules"/f"{m.module_id}.sh").is_file() else "NOT LOADED"
        brief=[("TARGET",m.title),("KEY",m.key), ("DOMAIN",m.category),
               ("MODULE",f"modules/{m.module_id}.sh"),("ENTRY",m.function),("STATE",stat)]
        for i,(label,value) in enumerate(brief):
            y=8+i*2
            put(y,split+3,label,cyan); put(y+1,split+3,value,yellow if label=="TARGET" else white)
        put(h-7,split+3,"ENTER  →  OPEN MODULE",mag)
        put(h-6,split+3,"The module menu runs in its own shell.",white)
    else: put(8,split+3,"No matching modules.",yellow)

    put(h-5,0,"├"+"─"*(w-2)+"┤",cyan)
    put(h-4,2,"/  SEARCH",mag); put(h-4,18,query or "type to filter modules",white)
    put(h-3,2,f"{len(filtered):02d} RESULTS",yellow)
    put(h-2,2,message or "↑↓ move   Enter open   Tab category   / search   Backspace clear   g GUI   ? help   q quit",cyan)
    put(h-1,0,"╰"+"─"*(w-2)+"╯",cyan)
    return filtered,selected,scroll


def help_screen(stdscr):
    stdscr.erase(); h,w=stdscr.getmaxyx()
    lines=["FIELD CONSOLE / KEYBOARD MAP","","↑ ↓ / j k     move through modules","Tab            next category","/              search modules, IDs and groups","Backspace      clear search","Enter          open selected module menu","g              launch GTK desktop UI","q              exit","","Enter any module menu's 0 key to return here.","Press any key to return."]
    for i,line in enumerate(lines):
        try: stdscr.addnstr(max(0,(h-len(lines))//2)+i,max(0,(w-len(line))//2),line,max(0,w-2),curses.A_BOLD if i==0 else 0)
        except curses.error: pass
    stdscr.refresh(); stdscr.getch()


def run_tui(stdscr,modules:list[Module],root:Path):
    try: curses.curs_set(0)
    except curses.error: pass
    stdscr.keypad(True)
    try: curses.set_escdelay(25)
    except Exception: pass
    query="";category="ALL";selected=0;scroll=0;message=""
    categories=["ALL"]+list(dict.fromkeys(m.category for m in modules))
    while True:
        filtered,selected,scroll=draw(stdscr,modules,query,selected,scroll,category,message,root);message=""
        ch=stdscr.getch()
        if ch in (ord('q'),ord('Q')): return 0
        if ch in (curses.KEY_UP,ord('k')): selected=max(0,selected-1)
        elif ch in (curses.KEY_DOWN,ord('j')): selected=min(max(0,len(filtered)-1),selected+1)
        elif ch==9: category=categories[(categories.index(category)+1)%len(categories)];selected=scroll=0
        elif ch==ord('/'):
            h,w=stdscr.getmaxyx(); curses.echo()
            try: curses.curs_set(1)
            except curses.error: pass
            stdscr.move(h-4,18)
            try: query=stdscr.getstr(h-4,18,max(1,w-21)).decode('utf-8','replace')
            except curses.error: pass
            curses.noecho()
            try: curses.curs_set(0)
            except curses.error: pass
            selected=scroll=0
        elif ch in (curses.KEY_BACKSPACE,127,8): query=query[:-1];selected=scroll=0
        elif ch in (ord('?'),ord('h')): help_screen(stdscr)
        elif ch in (ord('g'),ord('G')):
            binpath=root/'native/builddir/imsisting-gui'
            if not binpath.exists(): binpath=root/'native/build/imsisting-gui'
            if binpath.exists():
                curses.endwin();subprocess.Popen([str(binpath)],cwd=root);message="GTK GUI launched. Return here to continue."
            else: message="GUI binary not built."
        elif ch in (curses.KEY_ENTER,10,13) and filtered:
            m=filtered[selected];curses.endwin()
            try: subprocess.run(["bash","-c",f"source {str(root/'imsisting.sh')!r}; {m.function}"],cwd=root)
            except KeyboardInterrupt: pass
            print("\nReturned to field console. Press Enter to continue.",flush=True)
            try: input()
            except EOFError: pass
            stdscr.clear()
        elif 32<=ch<=126 and chr(ch).isalnum(): query+=chr(ch).lower();selected=scroll=0


def main():
    ap=argparse.ArgumentParser(description="IMSIsting full-screen terminal dashboard")
    ap.add_argument("--root",type=Path,default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--version",action="version",version=os.environ.get("IMSISTING_VERSION","IMSIsting"))
    args=ap.parse_args(); text=(args.root/'imsisting.sh').read_text(encoding='utf-8')
    start=text.index('IMSISTING_MODULE_TABLE=(');end=text.index('\n)',start)
    modules=parse_table_text(text[start:end])
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get('TERM') in ('','dumb'):
        print("IMSIsting TUI needs an interactive terminal (TTY). Use --help, --list, or --gui.",file=sys.stderr);return 2
    return curses.wrapper(run_tui,modules,args.root)

if __name__=='__main__': raise SystemExit(main())
